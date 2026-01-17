// -------------------------------------------------------------------------------
// vault-cert-manager - Configuration Directory Tests
//
// Unit tests for directory-based configuration loading.
// -------------------------------------------------------------------------------

package config

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"os"
	"path/filepath"
	"testing"
)

// -------------------------------------------------------------------------
// TESTS
// -------------------------------------------------------------------------

// TestLoadConfig_Directory verifies loading and merging configs from a directory.
func TestLoadConfig_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create primary config with vault settings
	vaultConfig := `
vault:
  address: https://vault.example.com
  auth:
    token:
      value: test-token

prometheus:
  port: 9090
  refresh_interval: 10s

logging:
  level: info
  format: json
`

	// Create additional config with certificates
	certsConfig := `
certificates:
  - name: cert1
    role: role1
    common_name: cert1.example.com
    certificate: /tmp/cert1.crt
    key: /tmp/cert1.key
    ttl: 24h
  - name: cert2
    role: role2
    common_name: cert2.example.com
    certificate: /tmp/cert2.crt
    key: /tmp/cert2.key
    ttl: 48h
`

	err := os.WriteFile(filepath.Join(tmpDir, "vault.yml"), []byte(vaultConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(tmpDir, "certs.yml"), []byte(certsConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Test loading directory
	config, err := LoadConfig(tmpDir)
	if err != nil {
		t.Fatalf("Failed to load config from directory: %v", err)
	}

	// Verify vault settings are loaded
	if config.Vault.Address != "https://vault.example.com" {
		t.Error("Vault address not loaded correctly")
	}

	// Verify certificates are loaded
	if len(config.Certificates) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(config.Certificates))
	}

	// Verify logging config
	if config.Logging.Format != "json" {
		t.Errorf("Expected json format, got %s", config.Logging.Format)
	}
}

// TestLoadConfig_DirectoryWithNonYAMLFiles verifies non-YAML files are ignored.
func TestLoadConfig_DirectoryWithNonYAMLFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid YAML config
	validConfig := `
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
    ttl: 24h
`

	err := os.WriteFile(filepath.Join(tmpDir, "config.yml"), []byte(validConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create non-YAML files that should be ignored
	err = os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("# README"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(tmpDir, "script.sh"), []byte("#!/bin/bash"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	// Test loading directory
	config, err := LoadConfig(tmpDir)
	if err != nil {
		t.Fatalf("Failed to load config from directory: %v", err)
	}

	if len(config.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(config.Certificates))
	}
}
