# -------------------------------------------------------------------------------
# vault-cert-manager - Makefile
#
# Project: Munchbox / Author: Alex Freidah
#
# Build targets for the Vault certificate manager. Supports native and cross-
# compilation, testing, linting, Debian package generation via nfpm, and
# lintian validation for package quality checks.
# -------------------------------------------------------------------------------

.PHONY: help build build-linux build-linux-arm64 test test-all test-coverage test-integration \
        lint clean deps install run generate-mocks fmt vet check build-all dev-build \
        build-deb build-deb-arm64 lint-deb

# --- Build variables ---
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# --- Go toolchain ---
GOCMD = go
GOBUILD = CGO_ENABLED=0 $(GOCMD) build
GOTEST = $(GOCMD) test
GOMOD = $(GOCMD) mod
LDFLAGS = -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

# --- Output paths ---
BINARY = vault-cert-manager
BINARY_PATH = ./cmd/vault-cert-manager
BIN_DIR = ./bin
DEB_DIR = ./dist

default: help

# Show available targets and descriptions
help:
	@echo "Available targets:"
	@echo ""
	@awk '/^$$/ { desc = "" } /^# [^-#]/ { desc = substr($$0, 3) } /^[a-zA-Z0-9_-]+:/ && desc { gsub(/:.*/, "", $$1); printf "  %-20s %s\n", $$1, desc; desc = "" }' $(MAKEFILE_LIST)
	@echo ""

# --- Build Targets ---

# Build for current platform
build:
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) $(BINARY_PATH)

# Build for Linux amd64
build-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)-linux-amd64 $(BINARY_PATH)

# Build for Linux arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)-linux-arm64 $(BINARY_PATH)

# Build for all platforms
build-all: build-linux build-linux-arm64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)-darwin-amd64 $(BINARY_PATH)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)-darwin-arm64 $(BINARY_PATH)

# Build with debug info for development
dev-build:
	$(GOCMD) build -gcflags="all=-N -l" -o $(BIN_DIR)/$(BINARY) $(BINARY_PATH)

# --- Test Targets ---

# Run tests (use test-all for integration tests)
test:
	$(GOTEST) -v -short ./...

# Run all tests including integration tests
test-all:
	$(GOTEST) -v ./...

# Run tests with coverage report
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Run integration tests
test-integration:
	$(GOTEST) -v -tags=integration ./...

# --- Code Quality ---

# Run linting with golangci-lint
lint:
	golangci-lint run

# Format code
fmt:
	$(GOCMD) fmt ./...

# Run go vet
vet:
	$(GOCMD) vet ./...

# Run all quality checks
check: fmt vet lint test

# Generate mock files
generate-mocks:
	go generate ./...

# --- Dependencies ---

# Download and tidy dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# --- Installation ---

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) $(DEB_DIR)
	rm -f coverage.out coverage.html

# Install binary to /usr/local/bin
install: build
	sudo cp $(BIN_DIR)/$(BINARY) /usr/local/bin/

# Run with example config
run: build
	$(BIN_DIR)/$(BINARY) --config examples/config.yaml

# Show version info that would be embedded
version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Built:   $(BUILD_TIME)"

# --- Debian Packaging ---

# Build Debian package for amd64
build-deb: build-linux
	@mkdir -p $(DEB_DIR)
	@cp $(BIN_DIR)/$(BINARY)-linux-amd64 $(BIN_DIR)/$(BINARY)-linux
	VERSION=$(VERSION) GOARCH=amd64 nfpm package --packager deb --target $(DEB_DIR)/
	@rm -f $(BIN_DIR)/$(BINARY)-linux

# Build Debian package for arm64
build-deb-arm64: build-linux-arm64
	@mkdir -p $(DEB_DIR)
	@cp $(BIN_DIR)/$(BINARY)-linux-arm64 $(BIN_DIR)/$(BINARY)-linux
	VERSION=$(VERSION) GOARCH=arm64 nfpm package --packager deb --target $(DEB_DIR)/
	@rm -f $(BIN_DIR)/$(BINARY)-linux

# Lint Debian packages with lintian (uses Docker on macOS)
lint-deb:
ifeq ($(shell uname),Darwin)
	@for deb in $(DEB_DIR)/*.deb; do \
		echo "Linting $$deb (via Docker)..."; \
		docker run --rm -v $(CURDIR)/$(DEB_DIR):/pkg debian:bookworm-slim \
			sh -c "apt-get update -qq && apt-get install -qq -y lintian >/dev/null 2>&1 && lintian --verbose /pkg/$$(basename $$deb)" || true; \
	done
else
	@for deb in $(DEB_DIR)/*.deb; do \
		echo "Linting $$deb..."; \
		lintian --verbose $$deb || true; \
	done
endif
