package vault

import (
	"github.com/afreidah/vault-cert-manager/pkg/config"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/vault/api"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

// GCPAuthenticator implements GCP-based authentication
type GCPAuthenticator struct {
	config *config.GCPAuth
}

// NewGCPAuthenticator creates a new GCP authenticator
func NewGCPAuthenticator(config *config.GCPAuth) *GCPAuthenticator {
	return &GCPAuthenticator{
		config: config,
	}
}

// Authenticate performs GCP authentication with Vault
func (g *GCPAuthenticator) Authenticate(client *api.Client) error {
	var jwt string
	var err error

	switch g.config.Type {
	case "gce":
		jwt, err = g.getGCEJWT()
	case "iam":
		jwt, err = g.getIAMJWT()
	default:
		return fmt.Errorf("unsupported GCP auth type: %s", g.config.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to generate JWT for GCP auth: %w", err)
	}

	loginPath := fmt.Sprintf("auth/%s/login", g.config.MountPath)
	loginData := map[string]interface{}{
		"role": g.config.Role,
		"jwt":  jwt,
	}

	slog.Debug("Attempting GCP authentication",
		"type", g.config.Type,
		"role", g.config.Role,
		"mount_path", g.config.MountPath)

	resp, err := client.Logical().Write(loginPath, loginData)
	if err != nil {
		return fmt.Errorf("failed to authenticate with GCP: %w", err)
	}

	if resp == nil || resp.Auth == nil {
		return fmt.Errorf("no authentication information returned from GCP auth")
	}

	client.SetToken(resp.Auth.ClientToken)
	slog.Info("Successfully authenticated with GCP", "auth_type", g.config.Type)

	return nil
}

// getGCEJWT retrieves a JWT from the GCE metadata service
func (g *GCPAuthenticator) getGCEJWT() (string, error) {
	// GCE instances can get identity tokens directly from the metadata service
	metadataURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"

	// Add audience parameter - Vault expects the audience to be the Vault server
	req, err := http.NewRequest("GET", metadataURL+"?audience=vault&format=full", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create metadata request: %w", err)
	}

	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve GCE identity token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("metadata service returned status %d: %s", resp.StatusCode, string(body))
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read identity token: %w", err)
	}

	return string(token), nil
}

// getIAMJWT generates a JWT for IAM-based authentication
func (g *GCPAuthenticator) getIAMJWT() (string, error) {
	var creds []byte
	var err error

	if g.config.CredentialsFile != "" {
		// Load credentials from file
		creds, err = os.ReadFile(g.config.CredentialsFile)
		if err != nil {
			return "", fmt.Errorf("failed to read credentials file %s: %w", g.config.CredentialsFile, err)
		}
	} else {
		// Try to get credentials from environment or default location
		ctx := context.Background()
		defaultCreds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return "", fmt.Errorf("failed to find default GCP credentials: %w", err)
		}
		creds = defaultCreds.JSON
	}

	// Parse the service account key
	var keyData struct {
		Type                    string `json:"type"`
		ProjectID               string `json:"project_id"`
		PrivateKeyID            string `json:"private_key_id"`
		PrivateKey              string `json:"private_key"`
		ClientEmail             string `json:"client_email"`
		ClientID                string `json:"client_id"`
		AuthURI                 string `json:"auth_uri"`
		TokenURI                string `json:"token_uri"`
		AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
		ClientX509CertURL       string `json:"client_x509_cert_url"`
	}

	if err := json.Unmarshal(creds, &keyData); err != nil {
		return "", fmt.Errorf("failed to parse service account credentials: %w", err)
	}

	// Override service account if specified
	serviceAccount := keyData.ClientEmail
	if g.config.ServiceAccount != "" {
		serviceAccount = g.config.ServiceAccount
	}

	// Set JWT expiration
	exp := time.Now().Add(15 * time.Minute) // default 15 minutes
	if g.config.JWTExp != "" {
		if duration, err := time.ParseDuration(g.config.JWTExp); err == nil {
			exp = time.Now().Add(duration)
		}
	}

	// Create JWT config
	jwtConfig := &jwt.Config{
		Email:        serviceAccount,
		PrivateKey:   []byte(keyData.PrivateKey),
		PrivateKeyID: keyData.PrivateKeyID,
		TokenURL:     keyData.TokenURI,
		Audience:     "vault", // Vault expects this audience
		Expires:      exp.Sub(time.Now()),
	}

	// Generate the token
	token, err := jwtConfig.TokenSource(context.Background()).Token()
	if err != nil {
		return "", fmt.Errorf("failed to generate IAM JWT: %w", err)
	}

	return token.AccessToken, nil
}
