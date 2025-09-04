package metrics

import (
	"cert-manager/pkg/cert"
	"cert-manager/pkg/config"
	"cert-manager/pkg/health"
	"cert-manager/pkg/vault"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
)

func TestNewCollector(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := vault.NewMockClient(ctrl)
	certManager := cert.NewManager(mockClient)
	healthChecker := health.NewTCPChecker()

	collector := NewCollector(certManager, healthChecker)

	if collector == nil {
		t.Fatal("collector is nil")
	}

	if collector.certManager != certManager {
		t.Error("certificate manager mismatch")
	}

	if collector.healthChecker != healthChecker {
		t.Error("health checker mismatch")
	}

	if collector.registry == nil {
		t.Error("registry is nil")
	}
}

func TestCollector_UpdateMetrics(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := vault.NewMockClient(ctrl)
	certManager := cert.NewManager(mockClient)
	healthChecker := health.NewTCPChecker()
	collector := NewCollector(certManager, healthChecker)

	certConfig := &config.CertificateConfig{
		Name:        "test-cert",
		Role:        "test-role",
		CommonName:  "test.example.com",
		Certificate: "/tmp/test.crt",
		Key:         "/tmp/test.key",
		TTL:         24 * time.Hour,
	}

	err := certManager.AddCertificate(certConfig)
	if err != nil {
		t.Fatalf("failed to add certificate: %v", err)
	}

	collector.UpdateMetrics()

	if collector.renewalCounts == nil {
		t.Error("renewal counts should be initialized")
	}
}

func TestCollector_IncrementRenewalCounter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := vault.NewMockClient(ctrl)
	certManager := cert.NewManager(mockClient)
	healthChecker := health.NewTCPChecker()
	collector := NewCollector(certManager, healthChecker)

	collector.IncrementRenewalCounter("test-cert", "success")
	collector.IncrementRenewalCounter("test-cert", "error")
}
