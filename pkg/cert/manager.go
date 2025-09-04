package cert

import (
	"cert-manager/pkg/config"
	"cert-manager/pkg/vault"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type Manager struct {
	vaultClient vault.Client
	certificates map[string]*ManagedCertificate
}

type ManagedCertificate struct {
	Config         *config.CertificateConfig
	LastRenewed    time.Time
	NextRenewal    time.Time
	Certificate    *x509.Certificate
	Fingerprint    string
	RenewalJitter  time.Duration
}

func NewManager(vaultClient vault.Client) *Manager {
	return &Manager{
		vaultClient:  vaultClient,
		certificates: make(map[string]*ManagedCertificate),
	}
}

func (m *Manager) AddCertificate(certConfig *config.CertificateConfig) error {
	if _, exists := m.certificates[certConfig.Name]; exists {
		return fmt.Errorf("certificate %s already exists", certConfig.Name)
	}

	managed := &ManagedCertificate{
		Config: certConfig,
	}

	jitter := time.Duration(rand.Int63n(int64(time.Hour)))
	managed.RenewalJitter = jitter

	if err := m.loadExistingCertificate(managed); err != nil {
		slog.Debug("No existing certificate found, will issue new one", 
			"certificate", certConfig.Name, 
			"error", err)
	}

	m.certificates[certConfig.Name] = managed
	return nil
}

func (m *Manager) ProcessCertificates() error {
	for name, managed := range m.certificates {
		if m.needsRenewal(managed) {
			slog.Info("Certificate needs renewal", "certificate", name)
			if err := m.renewCertificate(managed); err != nil {
				slog.Error("Failed to renew certificate", 
					"certificate", name, 
					"error", err)
				continue
			}
		}

		if !m.certificateExists(managed) {
			slog.Info("Certificate does not exist on disk, issuing new certificate", 
				"certificate", name)
			if err := m.issueCertificate(managed); err != nil {
				slog.Error("Failed to issue certificate", 
					"certificate", name, 
					"error", err)
				continue
			}
		}
	}
	return nil
}

func (m *Manager) GetManagedCertificates() map[string]*ManagedCertificate {
	return m.certificates
}

func (m *Manager) needsRenewal(managed *ManagedCertificate) bool {
	if managed.Certificate == nil {
		return false
	}

	renewalThreshold := managed.Certificate.NotAfter.Add(-managed.Config.TTL/3 - managed.RenewalJitter)
	return time.Now().After(renewalThreshold)
}

func (m *Manager) certificateExists(managed *ManagedCertificate) bool {
	certExists := fileExists(managed.Config.Certificate)
	keyExists := fileExists(managed.Config.Key)

	if managed.Config.IsCombinedFile() {
		return certExists
	}

	return certExists && keyExists
}

func (m *Manager) renewCertificate(managed *ManagedCertificate) error {
	return m.issueCertificate(managed)
}

func (m *Manager) issueCertificate(managed *ManagedCertificate) error {
	certData, err := m.vaultClient.IssueCertificate(managed.Config)
	if err != nil {
		return fmt.Errorf("failed to issue certificate from vault: %w", err)
	}

	if err := m.writeCertificateToDisk(managed, certData); err != nil {
		return fmt.Errorf("failed to write certificate to disk: %w", err)
	}

	if err := m.loadExistingCertificate(managed); err != nil {
		return fmt.Errorf("failed to load newly issued certificate: %w", err)
	}

	managed.LastRenewed = time.Now()
	managed.NextRenewal = managed.Certificate.NotAfter.Add(-managed.Config.TTL/3 - managed.RenewalJitter)

	if managed.Config.OnChange != "" {
		if err := m.runOnChangeScript(managed.Config.OnChange); err != nil {
			slog.Warn("Failed to run on_change script", 
				"certificate", managed.Config.Name, 
				"error", err)
		}
	}

	slog.Info("Successfully issued/renewed certificate", 
		"certificate", managed.Config.Name)
	return nil
}

func (m *Manager) writeCertificateToDisk(managed *ManagedCertificate, certData *vault.CertificateData) error {
	if err := m.ensureDirectories(managed); err != nil {
		return err
	}

	fullCert := certData.Certificate
	if certData.CertificateChain != "" {
		fullCert += "\n" + certData.CertificateChain
	}

	if managed.Config.IsCombinedFile() {
		content := fullCert + "\n" + certData.PrivateKey
		if err := m.writeFileWithPermissions(managed.Config.Certificate, content, 0600, managed.Config.Owner, managed.Config.Group); err != nil {
			return fmt.Errorf("failed to write combined certificate file: %w", err)
		}
	} else {
		if err := m.writeFileWithPermissions(managed.Config.Certificate, fullCert, 0644, managed.Config.Owner, managed.Config.Group); err != nil {
			return fmt.Errorf("failed to write certificate file: %w", err)
		}
		if err := m.writeFileWithPermissions(managed.Config.Key, certData.PrivateKey, 0600, managed.Config.Owner, managed.Config.Group); err != nil {
			return fmt.Errorf("failed to write private key file: %w", err)
		}
	}

	return nil
}

func (m *Manager) loadExistingCertificate(managed *ManagedCertificate) error {
	certData, err := os.ReadFile(managed.Config.Certificate)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	managed.Certificate = cert
	managed.Fingerprint = m.calculateFingerprint(certData)

	return nil
}

func (m *Manager) calculateFingerprint(certData []byte) string {
	block, _ := pem.Decode(certData)
	if block == nil {
		return ""
	}
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:])
}

func (m *Manager) ensureDirectories(managed *ManagedCertificate) error {
	certDir := filepath.Dir(managed.Config.Certificate)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory %s: %w", certDir, err)
	}

	if !managed.Config.IsCombinedFile() {
		keyDir := filepath.Dir(managed.Config.Key)
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return fmt.Errorf("failed to create key directory %s: %w", keyDir, err)
		}
	}

	return nil
}

func (m *Manager) writeFileWithPermissions(filename, content string, mode os.FileMode, owner, group string) error {
	if err := os.WriteFile(filename, []byte(content), mode); err != nil {
		return err
	}

	if owner != "" || group != "" {
		if err := m.changeOwnership(filename, owner, group); err != nil {
			slog.Warn("Failed to change ownership", 
				"file", filename, 
				"error", err)
		}
	}

	return nil
}

func (m *Manager) changeOwnership(filename, owner, group string) error {
	var uid, gid int = -1, -1

	if owner != "" {
		if u, err := user.Lookup(owner); err == nil {
			if uid, err = strconv.Atoi(u.Uid); err != nil {
				return fmt.Errorf("invalid uid for user %s: %w", owner, err)
			}
		} else {
			return fmt.Errorf("user %s not found: %w", owner, err)
		}
	}

	if group != "" {
		if g, err := user.LookupGroup(group); err == nil {
			if gid, err = strconv.Atoi(g.Gid); err != nil {
				return fmt.Errorf("invalid gid for group %s: %w", group, err)
			}
		} else {
			return fmt.Errorf("group %s not found: %w", group, err)
		}
	}

	return syscall.Chown(filename, uid, gid)
}

func (m *Manager) runOnChangeScript(script string) error {
	cmd := exec.Command("sh", "-c", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("script failed with error %v: %s", err, string(output))
	}
	slog.Debug("On-change script executed successfully", 
		"output", string(output))
	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}