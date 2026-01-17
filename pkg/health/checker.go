// -------------------------------------------------------------------------------
// vault-cert-manager - Health Checker
//
// TCP-based health checking for certificate deployments. Validates TLS
// connections and retrieves remote certificate fingerprints to verify
// successful certificate deployment to target services.
// -------------------------------------------------------------------------------

// Package health provides TCP-based certificate health checking.
package health

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/cert"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// -------------------------------------------------------------------------
// INTERFACES
// -------------------------------------------------------------------------

// Checker defines the interface for certificate health checking.
type Checker interface {
	Check(managed *cert.ManagedCertificate) (*CheckResult, error)
}

// -------------------------------------------------------------------------
// TYPES
// -------------------------------------------------------------------------

// CheckResult holds the result of a health check operation.
type CheckResult struct {
	Success           bool
	Error             error
	RemoteFingerprint string
}

// TCPChecker performs health checks via TCP/TLS connections.
type TCPChecker struct{}

// -------------------------------------------------------------------------
// CONSTRUCTOR
// -------------------------------------------------------------------------

// NewTCPChecker creates a new TCP-based health checker.
func NewTCPChecker() *TCPChecker {
	return &TCPChecker{}
}

// -------------------------------------------------------------------------
// METHODS
// -------------------------------------------------------------------------

// Check performs a TLS health check and retrieves the remote certificate.
func (t *TCPChecker) Check(managed *cert.ManagedCertificate) (*CheckResult, error) {
	if managed.Config.HealthCheck == nil || managed.Config.HealthCheck.TCP == "" {
		return &CheckResult{Success: true}, nil
	}

	timeout := managed.Config.HealthCheck.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	conn, err := net.DialTimeout("tcp", managed.Config.HealthCheck.TCP, timeout)
	if err != nil {
		return &CheckResult{
			Success: false,
			Error:   fmt.Errorf("failed to connect to %s: %w", managed.Config.HealthCheck.TCP, err),
		}, nil
	}
	defer func() { _ = conn.Close() }()

	tlsConn, err := tls.Dial("tcp", managed.Config.HealthCheck.TCP, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return &CheckResult{
			Success: false,
			Error:   fmt.Errorf("failed to establish TLS connection to %s: %w", managed.Config.HealthCheck.TCP, err),
		}, nil
	}
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return &CheckResult{
			Success: false,
			Error:   fmt.Errorf("failed to set deadline: %w", err),
		}, nil
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &CheckResult{
			Success: false,
			Error:   fmt.Errorf("no certificates received from server"),
		}, nil
	}

	remoteCert := state.PeerCertificates[0]
	remoteFingerprint := t.calculateFingerprint(remoteCert)

	return &CheckResult{
		Success:           true,
		RemoteFingerprint: remoteFingerprint,
	}, nil
}

// calculateFingerprint computes a SHA256 fingerprint of the certificate.
func (t *TCPChecker) calculateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}
