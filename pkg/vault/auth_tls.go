// -------------------------------------------------------------------------------
// vault-cert-manager - TLS Certificate Authentication
//
// TLS certificate-based authentication for Vault. Configures mTLS transport
// with client certificates and performs the cert auth login flow.
// -------------------------------------------------------------------------------

package vault

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/config"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/hashicorp/vault/api"
)

// -------------------------------------------------------------------------
// TYPES
// -------------------------------------------------------------------------

// TLSAuthenticator implements TLS certificate-based Vault authentication.
type TLSAuthenticator struct {
	config *config.TLSAuth
}

// -------------------------------------------------------------------------
// CONSTRUCTOR
// -------------------------------------------------------------------------

// NewTLSAuthenticator creates a new TLS certificate authenticator.
func NewTLSAuthenticator(config *config.TLSAuth) *TLSAuthenticator {
	return &TLSAuthenticator{
		config: config,
	}
}

// -------------------------------------------------------------------------
// METHODS
// -------------------------------------------------------------------------

// Authenticate performs TLS certificate authentication with Vault.
func (t *TLSAuthenticator) Authenticate(client *api.Client) error {
	// Load the client certificate and key
	cert, err := tls.LoadX509KeyPair(t.config.CertFile, t.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate pair: %w", err)
	}

	// Get the current client config and update it with the certificate
	config := client.CloneConfig()
	if config.HttpClient == nil {
		config.HttpClient = api.DefaultConfig().HttpClient
	}

	// Clone the TLS config and add the client certificate
	if config.HttpClient.Transport == nil {
		config.HttpClient.Transport = &http.Transport{}
	}

	transport, ok := config.HttpClient.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("unable to configure TLS transport")
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}

	// Add the client certificate
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}

	// Create a new client with the updated transport
	newClient, err := api.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create TLS-enabled Vault client: %w", err)
	}

	// Prepare login data
	loginPath := fmt.Sprintf("auth/%s/login", t.config.MountPath)
	loginData := map[string]interface{}{}

	// Add name if specified (for role-based cert auth)
	if t.config.Name != "" {
		loginData["name"] = t.config.Name
	}

	slog.Debug("Attempting TLS certificate authentication",
		"cert_file", t.config.CertFile,
		"mount_path", t.config.MountPath,
		"name", t.config.Name)

	// Perform the certificate authentication
	resp, err := newClient.Logical().Write(loginPath, loginData)
	if err != nil {
		return fmt.Errorf("failed to authenticate with TLS certificate: %w", err)
	}

	if resp == nil || resp.Auth == nil {
		return fmt.Errorf("no authentication information returned from TLS cert auth")
	}

	// Set the token on the original client
	client.SetToken(resp.Auth.ClientToken)
	slog.Info("Successfully authenticated with TLS certificate")

	return nil
}
