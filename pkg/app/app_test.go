// -------------------------------------------------------------------------------
// vault-cert-manager - Application Tests
//
// Unit tests for the application lifecycle orchestration.
// -------------------------------------------------------------------------------

package app

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/config"
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// TESTS
// -------------------------------------------------------------------------

// TestNew verifies that a new App instance is created correctly.
func TestNew(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{
			Address: "https://vault.example.com",
			Auth: config.AuthConfig{
				Token: &config.TokenAuth{
					Value: "test-token",
				},
			},
		},
		Prometheus: config.PrometheusConfig{
			Port:            9090,
			RefreshInterval: 10 * time.Second,
		},
		Certificates: []config.CertificateConfig{
			{
				Name:        "test-cert",
				Role:        "test-role",
				CommonName:  "test.example.com",
				Certificate: "/tmp/test.crt",
				Key:         "/tmp/test.key",
				TTL:         24 * time.Hour,
			},
		},
	}

	app, err := New(cfg)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if app == nil {
		t.Fatal("app is nil")
	}

	if app.config != cfg {
		t.Error("config mismatch")
	}

	if app.certManager == nil {
		t.Error("cert manager is nil")
	}

	if app.healthChecker == nil {
		t.Error("health checker is nil")
	}

	if app.collector == nil {
		t.Error("collector is nil")
	}

	app.Stop()
}

// TestApp_Stop verifies that the application shuts down cleanly.
func TestApp_Stop(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{
			Address: "https://vault.example.com",
			Auth: config.AuthConfig{
				Token: &config.TokenAuth{
					Value: "test-token",
				},
			},
		},
		Prometheus: config.PrometheusConfig{
			Port:            9091,
			RefreshInterval: 10 * time.Second,
		},
		Certificates: []config.CertificateConfig{},
	}

	app, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	app.Stop()
}
