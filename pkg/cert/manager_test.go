// -------------------------------------------------------------------------------
// vault-cert-manager - Certificate Manager Tests
//
// Unit tests for certificate lifecycle management operations.
// -------------------------------------------------------------------------------

package cert

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/config"
	"cert-manager/pkg/vault"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
)

// -------------------------------------------------------------------------
// TESTS
// -------------------------------------------------------------------------

// TestNewManager verifies that a new Manager instance is created correctly.
func TestNewManager(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := vault.NewMockClient(ctrl)
	manager := NewManager(mockClient)

	if manager == nil {
		t.Fatal("manager is nil")
	}

	if len(manager.certificates) != 0 {
		t.Error("expected empty certificates map")
	}
}

// TestManager_AddCertificate verifies certificate registration.
func TestManager_AddCertificate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := vault.NewMockClient(ctrl)
	manager := NewManager(mockClient)

	certConfig := &config.CertificateConfig{
		Name:        "test-cert",
		Role:        "test-role",
		CommonName:  "test.example.com",
		Certificate: "/tmp/test.crt",
		Key:         "/tmp/test.key",
		TTL:         24 * time.Hour,
	}

	err := manager.AddCertificate(certConfig)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(manager.certificates) != 1 {
		t.Error("expected 1 certificate in map")
	}

	managed, exists := manager.certificates["test-cert"]
	if !exists {
		t.Error("certificate not found in map")
	}

	if managed.Config.Name != "test-cert" {
		t.Error("certificate name mismatch")
	}

	err = manager.AddCertificate(certConfig)
	if err == nil {
		t.Error("expected error for duplicate certificate")
	}
}

// TestManager_ProcessCertificates verifies certificate issuance workflow.
func TestManager_ProcessCertificates(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tmpDir := t.TempDir()

	mockClient := vault.NewMockClient(ctrl)
	manager := NewManager(mockClient)

	certConfig := &config.CertificateConfig{
		Name:        "test-cert",
		Role:        "test-role",
		CommonName:  "test.example.com",
		Certificate: filepath.Join(tmpDir, "test.crt"),
		Key:         filepath.Join(tmpDir, "test.key"),
		TTL:         24 * time.Hour,
	}

	mockClient.EXPECT().IssueCertificate(certConfig).Return(vault.CreateTestCertificateData(), nil)

	err := manager.AddCertificate(certConfig)
	if err != nil {
		t.Fatalf("failed to add certificate: %v", err)
	}

	err = manager.ProcessCertificates()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !fileExists(certConfig.Certificate) {
		t.Error("certificate file should exist")
	}

	if !fileExists(certConfig.Key) {
		t.Error("key file should exist")
	}
}

// TestManager_ProcessCertificates_CombinedFile verifies combined cert/key file handling.
func TestManager_ProcessCertificates_CombinedFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tmpDir := t.TempDir()
	combinedFile := filepath.Join(tmpDir, "combined.pem")

	mockClient := vault.NewMockClient(ctrl)
	manager := NewManager(mockClient)

	certConfig := &config.CertificateConfig{
		Name:        "test-cert",
		Role:        "test-role",
		CommonName:  "test.example.com",
		Certificate: combinedFile,
		Key:         combinedFile,
		TTL:         24 * time.Hour,
	}

	mockClient.EXPECT().IssueCertificate(certConfig).Return(vault.CreateTestCertificateData(), nil)

	err := manager.AddCertificate(certConfig)
	if err != nil {
		t.Fatalf("failed to add certificate: %v", err)
	}

	err = manager.ProcessCertificates()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !fileExists(combinedFile) {
		t.Error("combined certificate file should exist")
	}

	content, err := os.ReadFile(combinedFile)
	if err != nil {
		t.Fatalf("failed to read combined file: %v", err)
	}

	if len(content) == 0 {
		t.Error("combined file should not be empty")
	}
}

// TestManager_ProcessCertificates_VaultError verifies error handling on Vault failures.
func TestManager_ProcessCertificates_VaultError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tmpDir := t.TempDir()

	mockClient := vault.NewMockClient(ctrl)
	manager := NewManager(mockClient)

	certConfig := &config.CertificateConfig{
		Name:        "test-cert",
		Role:        "test-role",
		CommonName:  "test.example.com",
		Certificate: filepath.Join(tmpDir, "test.crt"),
		Key:         filepath.Join(tmpDir, "test.key"),
		TTL:         24 * time.Hour,
	}

	mockClient.EXPECT().IssueCertificate(certConfig).Return(nil, fmt.Errorf("vault error"))

	err := manager.AddCertificate(certConfig)
	if err != nil {
		t.Fatalf("failed to add certificate: %v", err)
	}

	err = manager.ProcessCertificates()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if fileExists(certConfig.Certificate) {
		t.Error("certificate file should not exist after vault error")
	}
}
