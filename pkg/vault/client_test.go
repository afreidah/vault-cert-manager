package vault

import (
	"cert-manager/pkg/config"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name      string
		config    *config.VaultConfig
		expectErr bool
	}{
		{
			name: "valid token config",
			config: &config.VaultConfig{
				Address: "https://vault.example.com",
				Auth: config.AuthConfig{
					Token: &config.TokenAuth{
						Value: "test-token",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "valid gcp config",
			config: &config.VaultConfig{
				Address: "https://vault.example.com",
				Auth: config.AuthConfig{
					GCP: &config.GCPAuth{
						Role:      "test-role",
						Type:      "gce",
						MountPath: "gcp",
					},
				},
			},
			expectErr: true, // Will fail due to no actual GCP metadata service
		},
		{
			name: "valid tls config",
			config: &config.VaultConfig{
				Address: "https://vault.example.com",
				Auth: config.AuthConfig{
					TLS: &config.TLSAuth{
						CertFile:  "/nonexistent/cert.pem",
						KeyFile:   "/nonexistent/key.pem",
						MountPath: "cert",
					},
				},
			},
			expectErr: true, // Will fail due to nonexistent cert files
		},
		{
			name: "no auth method",
			config: &config.VaultConfig{
				Address: "https://vault.example.com",
				Auth:    config.AuthConfig{},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if client == nil {
				t.Error("client is nil")
			}
		})
	}
}

func TestCertificateDataValidation(t *testing.T) {
	certData := &CertificateData{
		Certificate:  "test-certificate",
		PrivateKey:   "test-private-key",
		SerialNumber: "12345",
		Expiration:   time.Now().Add(24 * time.Hour),
	}

	if certData.Certificate == "" {
		t.Error("certificate should not be empty")
	}

	if certData.PrivateKey == "" {
		t.Error("private key should not be empty")
	}

	if certData.Expiration.Before(time.Now()) {
		t.Error("expiration should be in the future")
	}
}