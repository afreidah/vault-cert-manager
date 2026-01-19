// -------------------------------------------------------------------------------
// vault-cert-manager - Application Lifecycle
//
// Core application orchestration: initializes components, manages goroutines
// for certificate processing and metrics collection, and handles graceful
// shutdown coordination.
// -------------------------------------------------------------------------------

// Package app provides the main application lifecycle orchestration.
package app

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/cert"
	"cert-manager/pkg/config"
	"cert-manager/pkg/health"
	"cert-manager/pkg/logging"
	"cert-manager/pkg/metrics"
	"cert-manager/pkg/vault"
	"context"
	"log/slog"
	"sync"
	"time"
)

// -------------------------------------------------------------------------
// TYPES
// -------------------------------------------------------------------------

// App orchestrates the certificate manager application lifecycle.
type App struct {
	config        *config.Config
	certManager   *cert.Manager
	healthChecker health.Checker
	collector     *metrics.Collector
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// -------------------------------------------------------------------------
// CONSTRUCTOR
// -------------------------------------------------------------------------

// New creates a new App instance with the given configuration.
func New(cfg *config.Config) (*App, error) {
	logging.SetupLogger(&cfg.Logging)

	vaultClient, err := vault.NewClient(&cfg.Vault)
	if err != nil {
		return nil, err
	}

	certManager := cert.NewManager(vaultClient)
	healthChecker := health.NewTCPChecker()
	collector := metrics.NewCollector(certManager, healthChecker)

	for _, certConfig := range cfg.Certificates {
		if err := certManager.AddCertificate(&certConfig); err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &App{
		config:        cfg,
		certManager:   certManager,
		healthChecker: healthChecker,
		collector:     collector,
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// -------------------------------------------------------------------------
// LIFECYCLE
// -------------------------------------------------------------------------

// Run starts the application and its background workers.
func (a *App) Run() error {
	slog.Info("Starting cert-manager application")

	if err := a.certManager.ProcessCertificates(); err != nil {
		slog.Error("Error processing certificates", "error", err)
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.collector.StartServer(a.config.Prometheus.Port); err != nil {
			slog.Error("Metrics server error", "error", err)
		}
	}()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.runCertificateProcessor()
	}()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.runMetricsUpdater()
	}()

	return nil
}

// Stop gracefully shuts down the application and waits for workers to finish.
func (a *App) Stop() {
	slog.Info("Stopping cert-manager application")
	a.cancel()
	a.wg.Wait()
}

// ForceRotate triggers immediate rotation of all certificates.
func (a *App) ForceRotate() error {
	return a.certManager.ForceRotateAll()
}

// RunOnce processes certificates once and returns (for --rotate mode).
func (a *App) RunOnce() error {
	slog.Info("Running one-time certificate rotation")
	return a.certManager.ForceRotateAll()
}

// -------------------------------------------------------------------------
// BACKGROUND WORKERS
// -------------------------------------------------------------------------

// runCertificateProcessor periodically checks and renews certificates.
func (a *App) runCertificateProcessor() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if err := a.certManager.ProcessCertificates(); err != nil {
				slog.Error("Error processing certificates", "error", err)
			}
		}
	}
}

// runMetricsUpdater periodically updates Prometheus metrics.
func (a *App) runMetricsUpdater() {
	ticker := time.NewTicker(a.config.Prometheus.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.collector.UpdateMetrics()
		}
	}
}
