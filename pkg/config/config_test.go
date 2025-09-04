package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		expectErr bool
	}{
		{
			name: "valid token config",
			content: `
vault:
  address: https://vault.example.com
  auth:
    token:
      value: test-token

prometheus:
  port: 9090
  refresh_interval: 10s

certificates:
  - name: test-cert
    role: test-role
    common_name: test.example.com
    certificate: /tmp/test.crt
    key: /tmp/test.key
    ttl: 24h
`,
			expectErr: false,
		},
		{
			name: "valid gcp config",
			content: `
vault:
  address: https://vault.example.com
  auth:
    gcp:
      role: test-role
      type: gce

certificates:
  - name: test-cert
    role: test-role
    common_name: test.example.com
    certificate: /tmp/test.crt
    key: /tmp/test.key
`,
			expectErr: false,
		},
		{
			name: "missing vault address",
			content: `
vault:
  auth:
    token:
      value: test-token
certificates:
  - name: test-cert
    role: test-role
    common_name: test.example.com
    certificate: /tmp/test.crt
    key: /tmp/test.key
`,
			expectErr: true,
		},
		{
			name: "no auth method",
			content: `
vault:
  address: https://vault.example.com
  auth: {}
certificates:
  - name: test-cert
    role: test-role
    common_name: test.example.com
    certificate: /tmp/test.crt
    key: /tmp/test.key
`,
			expectErr: true,
		},
		{
			name: "duplicate certificate names",
			content: `
vault:
  address: https://vault.example.com
  auth:
    token:
      value: test-token
certificates:
  - name: test-cert
    role: test-role
    common_name: test.example.com
    certificate: /tmp/test.crt
    key: /tmp/test.key
  - name: test-cert
    role: test-role2
    common_name: test2.example.com
    certificate: /tmp/test2.crt
    key: /tmp/test2.key
`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")

			err := os.WriteFile(configFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatal(err)
			}

			config, err := LoadConfig(configFile)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if config == nil {
				t.Fatal("config is nil")
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		expectErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Vault: VaultConfig{
					Address: "https://vault.example.com",
					Auth: AuthConfig{
						Token: &TokenAuth{
							Value: "test-token",
						},
					},
				},
				Certificates: []CertificateConfig{
					{
						Name:        "test-cert",
						Role:        "test-role",
						CommonName:  "test.example.com",
						Certificate: "/tmp/test.crt",
						Key:         "/tmp/test.key",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "missing vault address",
			config: Config{
				Vault: VaultConfig{
					Auth: AuthConfig{
						Token: &TokenAuth{
							Value: "test-token",
						},
					},
				},
			},
			expectErr: true,
		},
		{
			name: "missing certificate name",
			config: Config{
				Vault: VaultConfig{
					Address: "https://vault.example.com",
					Auth: AuthConfig{
						Token: &TokenAuth{
							Value: "test-token",
						},
					},
				},
				Certificates: []CertificateConfig{
					{
						Role:        "test-role",
						CommonName:  "test.example.com",
						Certificate: "/tmp/test.crt",
						Key:         "/tmp/test.key",
					},
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.config)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.config.Prometheus.Port == 0 {
				if tt.config.Prometheus.Port != 9090 {
					t.Error("prometheus port should default to 9090")
				}
			}
		})
	}
}

func TestCertificateConfig_IsCombinedFile(t *testing.T) {
	tests := []struct {
		name     string
		cert     CertificateConfig
		expected bool
	}{
		{
			name: "separate files",
			cert: CertificateConfig{
				Certificate: "/tmp/cert.crt",
				Key:         "/tmp/cert.key",
			},
			expected: false,
		},
		{
			name: "combined file",
			cert: CertificateConfig{
				Certificate: "/tmp/cert.pem",
				Key:         "/tmp/cert.pem",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cert.IsCombinedFile()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
