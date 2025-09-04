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
			name: "valid config",
			config: &config.VaultConfig{
				Address: "https://vault.example.com",
				Token:   "test-token",
			},
			expectErr: false,
		},
		{
			name: "invalid address",
			config: &config.VaultConfig{
				Address: "invalid-url",
				Token:   "test-token",
			},
			expectErr: false,
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