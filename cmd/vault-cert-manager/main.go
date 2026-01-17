// -------------------------------------------------------------------------------
// vault-cert-manager - CLI Entry Point
//
// Project: Munchbox / Author: Alex Freidah
//
// Automated certificate lifecycle manager for HashiCorp Vault PKI. Issues,
// renews, and deploys TLS certificates based on configurable policies with
// Prometheus metrics and health checking.
// -------------------------------------------------------------------------------

package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"cert-manager/pkg/app"
	"cert-manager/pkg/config"

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

	pflag.StringVarP(&configPath, "config", "c", "", "Path to config file or directory")
	pflag.BoolVarP(&showVersion, "version", "v", false, "Show version information")
	pflag.Parse()

	if showVersion {
		fmt.Printf("vault-cert-manager %s (commit: %s, built: %s)\n", version, commit, buildTime)
		os.Exit(0)
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

	// --- Initialize and start application ---
	application, err := app.New(cfg)
	if err != nil {
		slog.Error("Failed to create application", "error", err)
		os.Exit(1)
	}

	if err := application.Run(); err != nil {
		slog.Error("Failed to start application", "error", err)
		os.Exit(1)
	}

	slog.Info("Application started",
		"version", version,
		"commit", commit,
	)

	// --- Wait for shutdown signal ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// --- Graceful shutdown ---
	slog.Info("Shutdown signal received, stopping application...")
	application.Stop()
	slog.Info("Application stopped")
}
