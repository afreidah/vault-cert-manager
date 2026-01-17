package health

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

type Checker interface {
	Check(managed *cert.ManagedCertificate) (*CheckResult, error)
}

type CheckResult struct {
	Success           bool
	Error             error
	RemoteFingerprint string
}

type TCPChecker struct{}

func NewTCPChecker() *TCPChecker {
	return &TCPChecker{}
}

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

func (t *TCPChecker) calculateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}
