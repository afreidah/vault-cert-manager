// -------------------------------------------------------------------------------
// vault-cert-manager - Vault Client
//
// HashiCorp Vault client wrapper for PKI certificate issuance. Handles
// client initialization, authentication, and certificate requests with
// support for SANs, IP SANs, TTL, and certificate chain retrieval.
// -------------------------------------------------------------------------------

// Package vault provides HashiCorp Vault PKI client integration.
package vault

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"cert-manager/pkg/config"

	"github.com/hashicorp/vault/api"
)

// -------------------------------------------------------------------------
// INTERFACES
// -------------------------------------------------------------------------

// Client defines the interface for Vault PKI operations.
type Client interface {
	IssueCertificate(certConfig *config.CertificateConfig) (*CertificateData, error)
}

// -------------------------------------------------------------------------
// TYPES
// -------------------------------------------------------------------------

// VaultClient wraps the HashiCorp Vault API client.
type VaultClient struct {
	client        *api.Client
	pkiMount      string
	authenticator Authenticator
	authConfig    *config.AuthConfig
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// CertificateData holds the certificate response from Vault PKI.
type CertificateData struct {
	Certificate      string
	PrivateKey       string
	CertificateChain string
	SerialNumber     string
	Expiration       time.Time
}

// -------------------------------------------------------------------------
// CONSTRUCTOR
// -------------------------------------------------------------------------

// NewClient creates a new authenticated Vault client.
func NewClient(vaultConfig *config.VaultConfig) (*VaultClient, error) {
	cfg := &api.Config{
		Address: vaultConfig.Address,
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Create and execute the appropriate authenticator
	authenticator, err := CreateAuthenticator(&vaultConfig.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	if err := authenticator.Authenticate(client); err != nil {
		return nil, fmt.Errorf("failed to authenticate with vault: %w", err)
	}

	pkiMount := vaultConfig.PKIMount
	if pkiMount == "" {
		pkiMount = "pki"
	}

	ctx, cancel := context.WithCancel(context.Background())

	vc := &VaultClient{
		client:        client,
		pkiMount:      pkiMount,
		authenticator: authenticator,
		authConfig:    &vaultConfig.Auth,
		ctx:           ctx,
		cancel:        cancel,
	}

	// Start token renewal goroutine
	go vc.tokenRenewalLoop()

	return vc, nil
}

// Close stops the token renewal goroutine.
func (v *VaultClient) Close() {
	v.cancel()
}

// tokenRenewalLoop periodically renews or re-authenticates the Vault token.
func (v *VaultClient) tokenRenewalLoop() {
	// Renew every 45 minutes (before the default 1-hour TTL expires)
	ticker := time.NewTicker(45 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			if err := v.renewToken(); err != nil {
				slog.Error("Failed to renew Vault token, re-authenticating", "error", err)
				if err := v.reAuthenticate(); err != nil {
					slog.Error("Failed to re-authenticate with Vault", "error", err)
				}
			}
		}
	}
}

// renewToken attempts to renew the current Vault token.
func (v *VaultClient) renewToken() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	secret, err := v.client.Auth().Token().RenewSelf(0)
	if err != nil {
		return fmt.Errorf("token renewal failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("empty response from token renewal")
	}

	slog.Info("Successfully renewed Vault token", "ttl", secret.Auth.LeaseDuration)
	return nil
}

// reAuthenticate performs a fresh authentication with Vault.
func (v *VaultClient) reAuthenticate() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.authenticator.Authenticate(v.client); err != nil {
		return fmt.Errorf("re-authentication failed: %w", err)
	}

	slog.Info("Successfully re-authenticated with Vault")
	return nil
}

// -------------------------------------------------------------------------
// METHODS
// -------------------------------------------------------------------------

// IssueCertificate requests a new certificate from Vault PKI.
func (v *VaultClient) IssueCertificate(certConfig *config.CertificateConfig) (*CertificateData, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	path := fmt.Sprintf("%s/issue/%s", v.pkiMount, certConfig.Role)

	data := map[string]interface{}{
		"common_name": certConfig.CommonName,
		"format":      "pem",
	}

	if certConfig.TTL > 0 {
		data["ttl"] = certConfig.TTL.String()
	}

	if len(certConfig.AltNames) > 0 {
		data["alt_names"] = strings.Join(certConfig.AltNames, ",")
	}

	if len(certConfig.IPSans) > 0 {
		var validIPs []string
		for _, ip := range certConfig.IPSans {
			if net.ParseIP(ip) != nil {
				validIPs = append(validIPs, ip)
			}
		}
		if len(validIPs) > 0 {
			data["ip_sans"] = strings.Join(validIPs, ",")
		}
	}

	resp, err := v.client.Logical().Write(path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate from vault: %w", err)
	}

	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("empty response from vault")
	}

	certificate, ok := resp.Data["certificate"].(string)
	if !ok || certificate == "" {
		return nil, fmt.Errorf("certificate not found in vault response")
	}

	privateKey, ok := resp.Data["private_key"].(string)
	if !ok || privateKey == "" {
		return nil, fmt.Errorf("private_key not found in vault response")
	}

	var certificateChain string
	if chain, ok := resp.Data["ca_chain"]; ok {
		if chainSlice, ok := chain.([]interface{}); ok {
			var chainParts []string
			for _, part := range chainSlice {
				if chainStr, ok := part.(string); ok {
					chainParts = append(chainParts, chainStr)
				}
			}
			if len(chainParts) > 0 {
				certificateChain = strings.Join(chainParts, "\n")
			}
		}
	}

	if certificateChain == "" {
		if issuingCA, ok := resp.Data["issuing_ca"].(string); ok && issuingCA != "" {
			certificateChain = issuingCA
		}
	}

	serialNumber, _ := resp.Data["serial_number"].(string)

	var expiration time.Time
	if exp, ok := resp.Data["expiration"].(int64); ok {
		expiration = time.Unix(exp, 0)
	}

	return &CertificateData{
		Certificate:      certificate,
		PrivateKey:       privateKey,
		CertificateChain: certificateChain,
		SerialNumber:     serialNumber,
		Expiration:       expiration,
	}, nil
}
