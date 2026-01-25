// -------------------------------------------------------------------------------
// vault-cert-manager - CLI Entry Point
//
// Automated certificate lifecycle manager for HashiCorp Vault PKI. Issues,
// renews, and deploys TLS certificates based on configurable policies with
// Prometheus metrics and health checking.
// -------------------------------------------------------------------------------

// Package main provides the CLI entry point for vault-cert-manager.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cert-manager/pkg/app"
	"cert-manager/pkg/config"
	"cert-manager/pkg/web"

	"github.com/spf13/pflag"
)

// -------------------------------------------------------------------------
// BUILD METADATA
// -------------------------------------------------------------------------

var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

// -------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------

func main() {
	// --- Parse command line flags ---
	var configPath string
	var showVersion bool
	var rotateNow bool
	var aggregatorMode bool
	var consulAddr string
	var serviceName string
	var aggregatorPort int
	var rotateTimeout int

	pflag.StringVarP(&configPath, "config", "c", "", "Path to config file or directory")
	pflag.BoolVarP(&showVersion, "version", "v", false, "Show version information")
	pflag.BoolVarP(&rotateNow, "rotate", "r", false, "Force rotate all certificates and exit")
	pflag.BoolVarP(&aggregatorMode, "aggregator", "a", false, "Run in aggregator mode (centralized dashboard)")
	pflag.StringVar(&consulAddr, "consul-addr", "http://localhost:8500", "Consul HTTP address for service discovery")
	pflag.StringVar(&serviceName, "service-name", "vault-cert-manager", "Consul service name to discover")
	pflag.IntVarP(&aggregatorPort, "port", "p", 9102, "Port for aggregator dashboard")
	pflag.IntVar(&rotateTimeout, "timeout", 120, "Timeout in seconds for rotate operations (aggregator mode)")
	pflag.Parse()

	if showVersion {
		fmt.Printf("vault-cert-manager %s (commit: %s, built: %s)\n", version, commit, buildTime)
		os.Exit(0)
	}

	// --- Aggregator mode ---
	if aggregatorMode {
		slog.Info("Starting aggregator mode",
			"version", version,
			"commit", commit,
			"consul", consulAddr,
			"service", serviceName,
			"port", aggregatorPort,
			"timeout", rotateTimeout,
		)
		aggregator := web.NewAggregator(consulAddr, serviceName, time.Duration(rotateTimeout)*time.Second)
		if err := aggregator.StartServer(aggregatorPort); err != nil {
			slog.Error("Aggregator server failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if configPath == "" {
		slog.Error("Config path is required. Use --config or -c flag.")
		os.Exit(1)
	}

	// --- Load configuration ---
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// --- Initialize application ---
	application, err := app.New(cfg)
	if err != nil {
		slog.Error("Failed to create application", "error", err)
		os.Exit(1)
	}

	// --- One-shot rotation mode ---
	if rotateNow {
		slog.Info("Running one-time certificate rotation",
			"version", version,
			"commit", commit,
		)
		if err := application.RunOnce(); err != nil {
			slog.Error("Certificate rotation failed", "error", err)
			os.Exit(1)
		}
		slog.Info("Certificate rotation completed successfully")
		os.Exit(0)
	}

	// --- Daemon mode ---
	if err := application.Run(); err != nil {
		slog.Error("Failed to start application", "error", err)
		os.Exit(1)
	}

	slog.Info("Application started",
		"version", version,
		"commit", commit,
	)

	// --- Signal handling ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			slog.Info("SIGHUP received, forcing certificate rotation...")
			if err := application.ForceRotate(); err != nil {
				slog.Error("Force rotation failed", "error", err)
			} else {
				slog.Info("Force rotation completed")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			slog.Info("Shutdown signal received, stopping application...")
			application.Stop()
			slog.Info("Application stopped")
			os.Exit(0)
		}
	}
}
