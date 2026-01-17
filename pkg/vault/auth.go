package vault

import (
	"github.com/afreidah/vault-cert-manager/pkg/config"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// Authenticator interface defines methods for authenticating with Vault
type Authenticator interface {
	Authenticate(client *api.Client) error
}

// CreateAuthenticator creates the appropriate authenticator based on the auth configuration
func CreateAuthenticator(authConfig *config.AuthConfig) (Authenticator, error) {
	if authConfig.Token != nil {
		return NewTokenAuthenticator(authConfig.Token), nil
	}

	if authConfig.GCP != nil {
		return NewGCPAuthenticator(authConfig.GCP), nil
	}

	if authConfig.TLS != nil {
		return NewTLSAuthenticator(authConfig.TLS), nil
	}

	return nil, fmt.Errorf("no valid authentication method found")
}
