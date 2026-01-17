package main

import (
	"cert-manager/pkg/app"
	"cert-manager/pkg/config"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIntegration_CompleteWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	certDir := filepath.Join(tmpDir, "certs")

	err := os.MkdirAll(certDir, 0755)
	if err != nil {
		t.Fatalf("failed to create cert directory: %v", err)
	}

	configContent := `
vault:
  address: https://vault.example.com
  auth:
    token:
      value: test-token

prometheus:
  port: 9092
  refresh_interval: 1s

certificates:
  - name: test-integration-cert
    role: test-role
    common_name: test.example.com
    certificate: ` + filepath.Join(certDir, "test.crt") + `
    key: ` + filepath.Join(certDir, "test.key") + `
    ttl: 1h
    alt_names:
      - test.example.com
      - alt.example.com
`

	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	application, err := app.New(cfg)
	if err != nil {
		t.Fatalf("failed to create application: %v", err)
	}

	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if err := application.Run(); err != nil {
			t.Logf("application run error (expected): %v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	application.Stop()

	if cfg.Vault.Address != "https://vault.example.com" {
		t.Error("vault address mismatch")
	}

	if cfg.Prometheus.Port != 9092 {
		t.Error("prometheus port mismatch")
	}

	if len(cfg.Certificates) != 1 {
		t.Error("expected 1 certificate")
	}

	cert := cfg.Certificates[0]
	if cert.Name != "test-integration-cert" {
		t.Error("certificate name mismatch")
	}

	if len(cert.AltNames) != 2 {
		t.Error("expected 2 alt names")
	}
}

func TestIntegration_MultipleConfigFiles(t *testing.T) {
	tmpDir := t.TempDir()

	config1Content := `
vault:
  address: https://vault1.example.com
  auth:
    token:
      value: token1

prometheus:
  port: 9093
  refresh_interval: 2s

certificates:
  - name: cert1
    role: role1
    common_name: cert1.example.com
    certificate: /tmp/cert1.crt
    key: /tmp/cert1.key
`

	config2Content := `
vault:
  address: https://vault2.example.com
  auth:
    token:
      value: token2

certificates:
  - name: cert2
    role: role2
    common_name: cert2.example.com
    certificate: /tmp/cert2.crt
    key: /tmp/cert2.key
`

	config1File := filepath.Join(tmpDir, "config1.yaml")
	config2File := filepath.Join(tmpDir, "config2.yaml")

	err := os.WriteFile(config1File, []byte(config1Content), 0644)
	if err != nil {
		t.Fatalf("failed to write config1: %v", err)
	}

	err = os.WriteFile(config2File, []byte(config2Content), 0644)
	if err != nil {
		t.Fatalf("failed to write config2: %v", err)
	}

	cfg1, err := config.LoadConfig(config1File)
	if err != nil {
		t.Fatalf("failed to load config1: %v", err)
	}

	cfg2, err := config.LoadConfig(config2File)
	if err != nil {
		t.Fatalf("failed to load config2: %v", err)
	}

	cfg1.Certificates = append(cfg1.Certificates, cfg2.Certificates...)

	if len(cfg1.Certificates) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(cfg1.Certificates))
	}

	certNames := make(map[string]bool)
	for _, cert := range cfg1.Certificates {
		certNames[cert.Name] = true
	}

	if !certNames["cert1"] {
		t.Error("cert1 not found")
	}

	if !certNames["cert2"] {
		t.Error("cert2 not found")
	}
}
