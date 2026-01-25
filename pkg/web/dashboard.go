// -------------------------------------------------------------------------------
// vault-cert-manager - Web Dashboard
//
// Simple web UI for viewing certificate status and triggering manual rotation.
// Served alongside Prometheus metrics on the same port.
// -------------------------------------------------------------------------------

// Package web provides a simple dashboard for certificate management.
package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"cert-manager/pkg/cert"
	"cert-manager/pkg/health"
)

//go:embed templates/*.html
var templateFS embed.FS

// Dashboard provides HTTP handlers for the web interface.
type Dashboard struct {
	certManager   *cert.Manager
	healthChecker health.Checker
	templates     *template.Template
}

// CertStatus represents certificate status for the dashboard.
type CertStatus struct {
	Name              string    `json:"name"`
	CommonName        string    `json:"common_name"`
	NotAfter          time.Time `json:"not_after"`
	DaysLeft          int       `json:"days_left"`
	Fingerprint       string    `json:"fingerprint"`
	MemoryFingerprint string    `json:"memory_fingerprint,omitempty"`
	OutOfSync         bool      `json:"out_of_sync"`
	LastRenewed       time.Time `json:"last_renewed"`
	Status            string    `json:"status"` // "healthy", "expiring", "critical", "out_of_sync"
}

// NewDashboard creates a new dashboard instance.
func NewDashboard(certManager *cert.Manager, healthChecker health.Checker) *Dashboard {
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "Never"
			}
			return t.Format("2006-01-02 15:04:05")
		},
	}).ParseFS(templateFS, "templates/*.html"))

	return &Dashboard{
		certManager:   certManager,
		healthChecker: healthChecker,
		templates:     tmpl,
	}
}

// RegisterHandlers registers the dashboard HTTP handlers.
func (d *Dashboard) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", d.handleDashboard)
	mux.HandleFunc("/api/status", d.handleAPIStatus)
	mux.HandleFunc("/api/rotate/all", d.handleAPIRotateAll)
	mux.HandleFunc("/api/rotate/", d.handleAPIRotateCert)
}

// handleDashboard serves the main dashboard page.
func (d *Dashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	statuses := d.getCertStatuses()

	data := struct {
		Hostname string
		Certs    []CertStatus
	}{
		Hostname: getHostname(),
		Certs:    statuses,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		slog.Error("Failed to render dashboard", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleAPIStatus returns certificate status as JSON.
func (d *Dashboard) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	statuses := d.getCertStatuses()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statuses)
}

// handleAPIRotateAll forces rotation of all certificates.
func (d *Dashboard) handleAPIRotateAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	slog.Info("API request to rotate all certificates")
	if err := d.certManager.ForceRotateAll(); err != nil {
		slog.Error("Failed to rotate certificates", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "All certificates rotated"})
}

// handleAPIRotateCert forces rotation of a specific certificate.
func (d *Dashboard) handleAPIRotateCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract cert name from path: /api/rotate/{name}
	certName := strings.TrimPrefix(r.URL.Path, "/api/rotate/")
	if certName == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Certificate name required"})
		return
	}

	slog.Info("API request to rotate certificate", "certificate", certName)
	if err := d.certManager.ForceRotate(certName); err != nil {
		slog.Error("Failed to rotate certificate", "certificate", certName, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Certificate rotated", "name": certName})
}

// getCertStatuses builds status info for all managed certificates.
func (d *Dashboard) getCertStatuses() []CertStatus {
	var statuses []CertStatus

	for name, managed := range d.certManager.GetManagedCertificates() {
		status := CertStatus{
			Name:        name,
			CommonName:  managed.Config.CommonName,
			Fingerprint: managed.Fingerprint,
			LastRenewed: managed.LastRenewed,
		}

		if managed.Certificate != nil {
			status.NotAfter = managed.Certificate.NotAfter
			status.DaysLeft = int(time.Until(managed.Certificate.NotAfter).Hours() / 24)

			switch {
			case status.DaysLeft <= 7:
				status.Status = "critical"
			case status.DaysLeft <= 30:
				status.Status = "expiring"
			default:
				status.Status = "healthy"
			}
		} else {
			status.Status = "unknown"
		}

		// Check if certificate is out of sync (disk != memory)
		if d.healthChecker != nil && managed.Config.HealthCheck != nil {
			result, err := d.healthChecker.Check(managed)
			if err == nil && result.Success && result.RemoteFingerprint != "" {
				status.MemoryFingerprint = result.RemoteFingerprint
				if managed.Fingerprint != "" && result.RemoteFingerprint != managed.Fingerprint {
					status.OutOfSync = true
				}
			}
		}

		statuses = append(statuses, status)
	}

	return statuses
}

func getHostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}
