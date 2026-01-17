package vault

import (
	"cert-manager/pkg/config"

	"github.com/hashicorp/vault/api"
)

// TokenAuthenticator implements token-based authentication
type TokenAuthenticator struct {
	config *config.TokenAuth
}

// NewTokenAuthenticator creates a new token authenticator
func NewTokenAuthenticator(config *config.TokenAuth) *TokenAuthenticator {
	return &TokenAuthenticator{
		config: config,
	}
}

// Authenticate sets the token on the Vault client
func (t *TokenAuthenticator) Authenticate(client *api.Client) error {
	client.SetToken(t.config.Value)
	return nil
}
