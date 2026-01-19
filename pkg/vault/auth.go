// -------------------------------------------------------------------------------
// vault-cert-manager - Authenticator Interface
//
// Defines the Authenticator interface and factory function for creating
// authentication handlers based on configuration (token, GCP, or TLS).
// -------------------------------------------------------------------------------

package vault

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/config"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// -------------------------------------------------------------------------
// INTERFACES
// -------------------------------------------------------------------------

// Authenticator defines the interface for Vault authentication methods.
type Authenticator interface {
	Authenticate(client *api.Client) error
}

// -------------------------------------------------------------------------
// PUBLIC FUNCTIONS
// -------------------------------------------------------------------------

// CreateAuthenticator creates an authenticator based on the auth configuration.
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

	if authConfig.AppRole != nil {
		return NewAppRoleAuthenticator(authConfig.AppRole), nil
	}

	return nil, fmt.Errorf("no valid authentication method found")
}
