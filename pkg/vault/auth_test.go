package vault

import (
	"cert-manager/pkg/config"
	"fmt"
	"testing"
)

func TestCreateAuthenticator(t *testing.T) {
	tests := []struct {
		name       string
		authConfig *config.AuthConfig
		expectErr  bool
		expectType string
	}{
		{
			name: "token authenticator",
			authConfig: &config.AuthConfig{
				Token: &config.TokenAuth{
					Value: "test-token",
				},
			},
			expectErr:  false,
			expectType: "*vault.TokenAuthenticator",
		},
		{
			name: "gcp authenticator",
			authConfig: &config.AuthConfig{
				GCP: &config.GCPAuth{
					Role:      "test-role",
					Type:      "gce",
					MountPath: "gcp",
				},
			},
			expectErr:  false,
			expectType: "*vault.GCPAuthenticator",
		},
		{
			name: "tls authenticator",
			authConfig: &config.AuthConfig{
				TLS: &config.TLSAuth{
					CertFile:  "/path/to/cert.pem",
					KeyFile:   "/path/to/key.pem",
					MountPath: "cert",
				},
			},
			expectErr:  false,
			expectType: "*vault.TLSAuthenticator",
		},
		{
			name:       "no auth method",
			authConfig: &config.AuthConfig{},
			expectErr:  true,
		},
		{
			name: "multiple auth methods",
			authConfig: &config.AuthConfig{
				Token: &config.TokenAuth{Value: "test-token"},
				GCP: &config.GCPAuth{
					Role: "test-role",
					Type: "gce",
				},
			},
			expectErr:  false,                       // CreateAuthenticator doesn't validate this, config validation does
			expectType: "*vault.TokenAuthenticator", // Token takes precedence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := CreateAuthenticator(tt.authConfig)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if auth == nil {
				t.Error("authenticator is nil")
				return
			}

			// Check the type if specified
			if tt.expectType != "" {
				authType := fmt.Sprintf("%T", auth)
				if authType != tt.expectType {
					t.Errorf("expected type %s, got %s", tt.expectType, authType)
				}
			}
		})
	}
}
