// -------------------------------------------------------------------------------
// vault-cert-manager - Metrics Collector
//
// Prometheus metrics for certificate lifecycle monitoring. Exposes gauges for
// certificate timestamps and fingerprints, counters for renewal operations,
// and integrates with health checks for deployment verification.
// -------------------------------------------------------------------------------

// Package metrics provides Prometheus metrics for certificate monitoring.
package metrics

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/cert"
	"cert-manager/pkg/health"
	"cert-manager/pkg/web"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// -------------------------------------------------------------------------
// TYPES
// -------------------------------------------------------------------------

// Collector gathers and exposes certificate metrics for Prometheus.
type Collector struct {
	certManager   *cert.Manager
	healthChecker health.Checker
	registry      *prometheus.Registry

	lastRenewedTimestamp *prometheus.GaugeVec
	notBeforeTimestamp   *prometheus.GaugeVec
	notAfterTimestamp    *prometheus.GaugeVec
	renewalsTotal        *prometheus.CounterVec
	fingerprintInfo      *prometheus.GaugeVec

	renewalCounts map[string]map[string]int
}

// -------------------------------------------------------------------------
// CONSTRUCTOR
// -------------------------------------------------------------------------

// NewCollector creates a new metrics collector with the given dependencies.
func NewCollector(certManager *cert.Manager, healthChecker health.Checker) *Collector {
	registry := prometheus.NewRegistry()

	c := &Collector{
		certManager:   certManager,
		healthChecker: healthChecker,
		registry:      registry,
		renewalCounts: make(map[string]map[string]int),

		lastRenewedTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "managed_cert_last_renewed_timestamp_seconds",
				Help: "The timestamp of the last successful certificate renewal, in seconds since the Unix epoch.",
			},
			[]string{"name"},
		),

		notBeforeTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "managed_cert_not_before_timestamp_seconds",
				Help: "The timestamp of the certificate not before date, in seconds since the Unix epoch.",
			},
			[]string{"name"},
		),

		notAfterTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "managed_cert_not_after_timestamp_seconds",
				Help: "The timestamp of the certificate not after date, in seconds since the Unix epoch.",
			},
			[]string{"name"},
		),

		renewalsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "managed_cert_renewals_total",
				Help: "The total number of certificate renewals.",
			},
			[]string{"name", "status"},
		),

		fingerprintInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "managed_cert_fingerprint_info",
				Help: "A static metric with value of 1, where the fingerprint is the SHA256 fingerprint of the certificate.",
			},
			[]string{"name", "fingerprint", "location"},
		),
	}

	registry.MustRegister(c.lastRenewedTimestamp)
	registry.MustRegister(c.notBeforeTimestamp)
	registry.MustRegister(c.notAfterTimestamp)
	registry.MustRegister(c.renewalsTotal)
	registry.MustRegister(c.fingerprintInfo)

	return c
}

// -------------------------------------------------------------------------
// PUBLIC METHODS
// -------------------------------------------------------------------------

// StartServer starts the HTTP server with Prometheus metrics and web dashboard.
func (c *Collector) StartServer(port int) error {
	mux := http.NewServeMux()

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{}))

	// Web dashboard
	dashboard := web.NewDashboard(c.certManager)
	dashboard.RegisterHandlers(mux)

	addr := fmt.Sprintf(":%d", port)
	slog.Info("Starting HTTP server", "address", addr, "endpoints", []string{"/", "/metrics", "/api/status", "/api/rotate/*"})

	return http.ListenAndServe(addr, mux)
}

// UpdateMetrics refreshes all certificate and health check metrics.
func (c *Collector) UpdateMetrics() {
	managedCerts := c.certManager.GetManagedCertificates()

	for name, managed := range managedCerts {
		c.updateCertificateMetrics(name, managed)
		c.updateHealthCheckMetrics(name, managed)
	}
}

// -------------------------------------------------------------------------
// PRIVATE METHODS
// -------------------------------------------------------------------------

// updateCertificateMetrics updates metrics for a single certificate.
func (c *Collector) updateCertificateMetrics(name string, managed *cert.ManagedCertificate) {
	if !managed.LastRenewed.IsZero() {
		c.lastRenewedTimestamp.WithLabelValues(name).Set(float64(managed.LastRenewed.Unix()))
	}

	if managed.Certificate != nil {
		c.notBeforeTimestamp.WithLabelValues(name).Set(float64(managed.Certificate.NotBefore.Unix()))
		c.notAfterTimestamp.WithLabelValues(name).Set(float64(managed.Certificate.NotAfter.Unix()))

		if managed.Fingerprint != "" {
			c.fingerprintInfo.WithLabelValues(name, managed.Fingerprint, "disk").Set(1)
		}
	}
}

// updateHealthCheckMetrics performs health check and updates fingerprint metrics.
func (c *Collector) updateHealthCheckMetrics(name string, managed *cert.ManagedCertificate) {
	if managed.Config.HealthCheck == nil {
		return
	}

	result, err := c.healthChecker.Check(managed)
	if err != nil {
		slog.Error("Health check error", "certificate", name, "error", err)
		return
	}

	if !result.Success {
		slog.Warn("Health check failed", "certificate", name, "error", result.Error)
		return
	}

	if result.RemoteFingerprint != "" {
		c.fingerprintInfo.WithLabelValues(name, result.RemoteFingerprint, "memory").Set(1)
	}
}

// IncrementRenewalCounter increments the renewal counter for a certificate.
func (c *Collector) IncrementRenewalCounter(name, status string) {
	c.renewalsTotal.WithLabelValues(name, status).Inc()
}
