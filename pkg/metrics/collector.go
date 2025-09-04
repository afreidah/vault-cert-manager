package metrics

import (
	"cert-manager/pkg/cert"
	"cert-manager/pkg/health"
	"fmt"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Collector struct {
	certManager   *cert.Manager
	healthChecker health.Checker
	registry      *prometheus.Registry

	lastRenewedTimestamp   *prometheus.GaugeVec
	notBeforeTimestamp     *prometheus.GaugeVec
	notAfterTimestamp      *prometheus.GaugeVec
	renewalsTotal          *prometheus.CounterVec
	fingerprintInfo        *prometheus.GaugeVec

	renewalCounts map[string]map[string]int
}

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

func (c *Collector) StartServer(port int) error {
	http.Handle("/metrics", promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{}))
	
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Starting Prometheus metrics server on %s", addr)
	
	return http.ListenAndServe(addr, nil)
}

func (c *Collector) UpdateMetrics() {
	managedCerts := c.certManager.GetManagedCertificates()

	for name, managed := range managedCerts {
		c.updateCertificateMetrics(name, managed)
		c.updateHealthCheckMetrics(name, managed)
	}
}

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

func (c *Collector) updateHealthCheckMetrics(name string, managed *cert.ManagedCertificate) {
	if managed.Config.HealthCheck == nil {
		return
	}

	result, err := c.healthChecker.Check(managed)
	if err != nil {
		log.Printf("Health check error for %s: %v", name, err)
		return
	}

	if !result.Success {
		log.Printf("Health check failed for %s: %v", name, result.Error)
		return
	}

	if result.RemoteFingerprint != "" {
		c.fingerprintInfo.WithLabelValues(name, result.RemoteFingerprint, "memory").Set(1)
	}
}

func (c *Collector) IncrementRenewalCounter(name, status string) {
	c.renewalsTotal.WithLabelValues(name, status).Inc()
}