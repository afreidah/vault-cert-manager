package health

import (
	"cert-manager/pkg/cert"
	"cert-manager/pkg/config"
	"testing"
	"time"
)

func TestNewTCPChecker(t *testing.T) {
	checker := NewTCPChecker()
	if checker == nil {
		t.Fatal("checker is nil")
	}
}

func TestTCPChecker_Check_NoHealthCheck(t *testing.T) {
	checker := NewTCPChecker()
	managed := &cert.ManagedCertificate{
		Config: &config.CertificateConfig{
			Name: "test-cert",
		},
	}

	result, err := checker.Check(managed)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !result.Success {
		t.Error("check should succeed when no health check configured")
	}
}

func TestTCPChecker_Check_InvalidHost(t *testing.T) {
	checker := NewTCPChecker()
	managed := &cert.ManagedCertificate{
		Config: &config.CertificateConfig{
			Name: "test-cert",
			HealthCheck: &config.HealthCheck{
				TCP:     "invalid-host:443",
				Timeout: 1 * time.Second,
			},
		},
	}

	result, err := checker.Check(managed)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result.Success {
		t.Error("check should fail for invalid host")
	}

	if result.Error == nil {
		t.Error("error should be set for failed check")
	}
}

func TestTCPChecker_calculateFingerprint(t *testing.T) {
	checker := NewTCPChecker()

	fingerprint := checker.calculateFingerprint(nil)
	if fingerprint != "" {
		t.Error("fingerprint should be empty for nil certificate")
	}
}