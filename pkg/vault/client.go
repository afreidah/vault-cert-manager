package vault

import (
	"cert-manager/pkg/config"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

type Client interface {
	IssueCertificate(certConfig *config.CertificateConfig) (*CertificateData, error)
}

type VaultClient struct {
	client *api.Client
}

type CertificateData struct {
	Certificate string
	PrivateKey  string
	SerialNumber string
	Expiration  time.Time
}

func NewClient(vaultConfig *config.VaultConfig) (*VaultClient, error) {
	cfg := &api.Config{
		Address: vaultConfig.Address,
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(vaultConfig.Token)

	return &VaultClient{
		client: client,
	}, nil
}

func (v *VaultClient) IssueCertificate(certConfig *config.CertificateConfig) (*CertificateData, error) {
	path := fmt.Sprintf("pki/issue/%s", certConfig.Role)

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

	serialNumber, _ := resp.Data["serial_number"].(string)

	var expiration time.Time
	if exp, ok := resp.Data["expiration"].(int64); ok {
		expiration = time.Unix(exp, 0)
	}

	return &CertificateData{
		Certificate:  certificate,
		PrivateKey:   privateKey,
		SerialNumber: serialNumber,
		Expiration:   expiration,
	}, nil
}