// -------------------------------------------------------------------------------
// vault-cert-manager - Logging
//
// Configures the global slog logger based on configuration settings.
// Supports JSON and text output formats with configurable log levels.
// -------------------------------------------------------------------------------

// Package logging provides slog logger configuration.
package logging

// -------------------------------------------------------------------------
// IMPORTS
// -------------------------------------------------------------------------

import (
	"cert-manager/pkg/config"
	"log/slog"
	"os"
	"strings"
)

// -------------------------------------------------------------------------
// PUBLIC FUNCTIONS
// -------------------------------------------------------------------------

// SetupLogger configures the global slog logger based on the given config.
func SetupLogger(cfg *config.LoggingConfig) {
	var level slog.Level

	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}
