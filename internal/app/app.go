package app

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

type App struct {
	config        *config.Config
	certManager   *cert.Manager
	healthChecker health.Checker
	collector     *metrics.Collector
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

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

func (a *App) Stop() {
	slog.Info("Stopping cert-manager application")
	a.cancel()
	a.wg.Wait()
}

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