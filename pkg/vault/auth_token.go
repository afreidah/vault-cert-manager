// -------------------------------------------------------------------------------
// vault-cert-manager - Token Authentication
//
// Token-based authentication for Vault. Simply sets the provided token
// on the Vault client for API access.
// -------------------------------------------------------------------------------

package vault

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/config"

	"github.com/hashicorp/vault/api"
)

// -------------------------------------------------------------------------
// TYPES
// -------------------------------------------------------------------------

// TokenAuthenticator implements token-based Vault authentication.
type TokenAuthenticator struct {
	config *config.TokenAuth
}

// -------------------------------------------------------------------------
// CONSTRUCTOR
// -------------------------------------------------------------------------

// NewTokenAuthenticator creates a new token authenticator.
func NewTokenAuthenticator(config *config.TokenAuth) *TokenAuthenticator {
	return &TokenAuthenticator{
		config: config,
	}
}

// -------------------------------------------------------------------------
// METHODS
// -------------------------------------------------------------------------

// Authenticate sets the token on the Vault client.
func (t *TokenAuthenticator) Authenticate(client *api.Client) error {
	client.SetToken(t.config.Value)
	return nil
}
