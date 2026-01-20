// -------------------------------------------------------------------------------
// vault-cert-manager - AppRole Authentication
//
// AppRole-based authentication for Vault. Authenticates using role_id and
// secret_id, which is the recommended method for machine/service authentication.
// Supports reading secret_id from a file for improved security.
// -------------------------------------------------------------------------------

package vault

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/config"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

// -------------------------------------------------------------------------
// TYPES
// -------------------------------------------------------------------------

// AppRoleAuthenticator implements AppRole-based Vault authentication.
type AppRoleAuthenticator struct {
	config *config.AppRoleAuth
}

// -------------------------------------------------------------------------
// CONSTRUCTOR
// -------------------------------------------------------------------------

// NewAppRoleAuthenticator creates a new AppRole authenticator.
func NewAppRoleAuthenticator(config *config.AppRoleAuth) *AppRoleAuthenticator {
	return &AppRoleAuthenticator{
		config: config,
	}
}

// -------------------------------------------------------------------------
// METHODS
// -------------------------------------------------------------------------

// Authenticate performs AppRole authentication with Vault.
func (a *AppRoleAuthenticator) Authenticate(client *api.Client) error {
	secretID, err := a.getSecretID()
	if err != nil {
		return fmt.Errorf("failed to get secret_id: %w", err)
	}

	mountPath := a.config.MountPath
	if mountPath == "" {
		mountPath = "approle"
	}

	loginPath := fmt.Sprintf("auth/%s/login", mountPath)
	loginData := map[string]interface{}{
		"role_id":   a.config.RoleID,
		"secret_id": secretID,
	}

	slog.Debug("Attempting AppRole authentication",
		"mount_path", mountPath,
		"role_id", a.config.RoleID)

	resp, err := client.Logical().Write(loginPath, loginData)
	if err != nil {
		return fmt.Errorf("failed to authenticate with AppRole: %w", err)
	}

	if resp == nil || resp.Auth == nil {
		return fmt.Errorf("no authentication information returned from AppRole auth")
	}

	client.SetToken(resp.Auth.ClientToken)
	slog.Info("Successfully authenticated with AppRole")

	return nil
}

// -------------------------------------------------------------------------
// PRIVATE METHODS
// -------------------------------------------------------------------------

// getSecretID retrieves the secret_id from config or file.
func (a *AppRoleAuthenticator) getSecretID() (string, error) {
	// Prefer secret_id_file over inline secret_id
	if a.config.SecretIDFile != "" {
		data, err := os.ReadFile(a.config.SecretIDFile)
		if err != nil {
			return "", fmt.Errorf("failed to read secret_id file %s: %w", a.config.SecretIDFile, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	if a.config.SecretID != "" {
		return a.config.SecretID, nil
	}

	return "", fmt.Errorf("either secret_id or secret_id_file must be specified")
}
