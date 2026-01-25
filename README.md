# vault-cert-manager

HashiCorp Vault PKI Certificate Lifecycle Manager

## Overview

Manages X.509 certificate issuance and renewal from HashiCorp Vault's PKI backend with automated lifecycle management, health monitoring, web dashboard, and Prometheus metrics.

This is a fork of the original cert-manager with significant enhancements for infrastructure automation.

## Quick Start

```bash
# Build
make build

# Run as daemon with config
./vault-cert-manager --config /etc/vault-cert-manager/config.yaml

# One-shot rotation (rotate all certs and exit)
./vault-cert-manager --config config.yaml --rotate

# Run as aggregator dashboard (centralized view of all instances)
./vault-cert-manager --aggregator --consul-addr http://consul:8500

# View metrics
curl http://localhost:9101/metrics

# View dashboard
open http://localhost:9101/
```

## Features

- **Automated Certificate Management**: Issues missing certificates, renews before expiration with jitter
- **Web Dashboard**: Per-node web UI showing certificate status with manual rotation buttons
- **Aggregator Mode**: Centralized dashboard discovering all instances via Consul service discovery
- **Out-of-Sync Detection**: Identifies certificates where disk differs from what services are serving
- **Force Rotation**: Trigger immediate rotation via SIGHUP, CLI flag, or REST API
- **Health Checks**: TCP-based validation comparing disk vs in-memory certificates
- **Prometheus Metrics**: Comprehensive metrics for monitoring certificate lifecycle
- **Flexible Configuration**: YAML-based config supporting multiple certificates and directories
- **Script Integration**: Optional post-change script execution for service reloads
- **Certificate Chains**: Automatic inclusion of intermediate certificates in output files
- **Structured Logging**: JSON or text format with configurable log levels

## Operating Modes

### Daemon Mode (Default)

Runs continuously, monitoring and renewing certificates as needed:

```bash
./vault-cert-manager --config /etc/vault-cert-manager/config.yaml
```

The daemon:
- Checks certificates on startup and periodically
- Renews certificates before expiration (with jitter to avoid thundering herd)
- Exposes Prometheus metrics and web dashboard on the configured port
- Responds to SIGHUP by forcing immediate rotation of all certificates

### One-Shot Mode

Rotates all certificates once and exits:

```bash
./vault-cert-manager --config config.yaml --rotate
```

Useful for:
- Initial certificate provisioning
- Cron-based rotation
- CI/CD pipelines

### Aggregator Mode

Runs a centralized dashboard that discovers all vault-cert-manager instances via Consul:

```bash
./vault-cert-manager --aggregator \
  --consul-addr http://consul:8500 \
  --service-name vault-cert-manager \
  --port 9102
```

The aggregator:
- Queries Consul for all registered vault-cert-manager services
- Displays certificate status from all nodes in a unified view
- Proxies rotation requests to individual nodes

### Out-of-Sync Detection

When a certificate has a `health_check` configured, the dashboard compares:
- **Disk fingerprint**: The certificate written to the filesystem
- **Memory fingerprint**: The certificate the service is actually serving via TLS

If these differ, the certificate is marked as "OUT OF SYNC" in the dashboard. This indicates the certificate was renewed but the service hasn't reloaded it yet.

The dashboard shows:
- Purple "OUT OF SYNC" badge next to affected certificates
- "Sync Now" button (instead of "Rotate") to trigger rotation and service reload
- Out-of-sync count in the aggregator summary bar

Clicking "Sync Now" rotates the certificate and runs the configured `on_change` script to reload the service.

## CLI Options

```
Usage:
  vault-cert-manager [flags]

Flags:
  -c, --config string         Path to config file or directory
  -v, --version               Show version information
  -r, --rotate                Force rotate all certificates and exit
  -a, --aggregator            Run in aggregator mode (centralized dashboard)
      --consul-addr string    Consul HTTP address for service discovery (default "http://localhost:8500")
      --service-name string   Consul service name to discover (default "vault-cert-manager")
  -p, --port int              Port for aggregator dashboard (default 9102)
```

## Configuration

### Basic Configuration

```yaml
vault:
  address: https://vault.example.com    # Required: Vault server URL
  skip_verify: false                    # Optional: skip TLS verification
  pki_mount: pki_int                    # Optional: PKI mount path (default: pki)
  auth:
    approle:                            # Recommended for production
      role_id: "xxx-xxx-xxx"
      secret_id_file: /etc/vault-cert-manager/secret_id

prometheus:
  port: 9101                            # Optional: metrics/dashboard port (default: 9090)
  refresh_interval: 30s                 # Optional: metrics refresh (default: 10s)

logging:
  level: info                           # Optional: debug|info|warn|error (default: info)
  format: text                          # Optional: text|json (default: text)

certificates:
  - name: web-cert                      # Required: unique certificate name
    role: web-server                    # Required: Vault PKI role
    common_name: www.example.com        # Required: certificate CN
    certificate: /etc/ssl/web.crt       # Required: output certificate path
    key: /etc/ssl/web.key               # Required: output private key path
    ttl: 720h                           # Optional: certificate lifetime (default: 24h)
    on_change: systemctl reload nginx   # Optional: command to run after renewal
    health_check:                       # Optional: health check configuration
      tcp: 127.0.0.1:443                # Required if health_check specified
      timeout: 5s                       # Optional: check timeout (default: 5s)
```

### Authentication Methods

#### AppRole Authentication (Recommended)

Best for automated deployments where credentials can be securely provisioned:

```yaml
vault:
  address: https://vault.example.com
  auth:
    approle:
      role_id: "xxx-xxx-xxx-xxx"        # Required: AppRole role ID
      secret_id: "yyy-yyy-yyy"          # Option 1: inline secret ID
      secret_id_file: /path/to/secret   # Option 2: read from file (recommended)
      mount_path: approle               # Optional: auth mount path (default: "approle")
```

#### Token Authentication

Simple but requires token management:

```yaml
vault:
  address: https://vault.example.com
  auth:
    token:
      value: hvs.your-vault-token
```

#### GCP Authentication

For workloads running on Google Cloud:

```yaml
vault:
  address: https://vault.example.com
  auth:
    gcp:
      role: your-gcp-role              # Required: GCP auth role in Vault
      type: gce                        # Required: "gce" or "iam"
      mount_path: gcp                  # Optional: auth mount path (default: "gcp")

      # For IAM type only:
      service_account: vault@project.iam.gserviceaccount.com
      jwt_exp: 15m                     # Optional: JWT expiration (default: 15m)
      credentials_file: /path/to/sa.json
```

#### TLS Certificate Authentication

For environments with existing PKI:

```yaml
vault:
  address: https://vault.example.com
  auth:
    tls:
      cert_file: /etc/vault/client.pem  # Required: client certificate
      key_file: /etc/vault/client.key   # Required: client private key
      name: client-role                 # Optional: role name
      mount_path: cert                  # Optional: auth mount path (default: "cert")
```

### Certificate Configuration Options

```yaml
certificates:
  - name: full-example                  # Required: unique identifier
    role: web-server                    # Required: Vault PKI role name
    common_name: www.example.com        # Required: certificate common name
    certificate: /etc/ssl/cert.pem      # Required: certificate output path
    key: /etc/ssl/key.pem               # Required: private key output path
    ttl: 720h                           # Optional: certificate lifetime (default: 24h)

    # Subject Alternative Names
    alt_names:                          # Optional: DNS alternative names
      - www.example.com
      - api.example.com
    ip_sans:                            # Optional: IP alternative names
      - 192.168.1.100
      - 127.0.0.1

    # Post-renewal actions
    on_change: "systemctl reload nginx" # Optional: command to execute after renewal

    # Health monitoring
    health_check:                       # Optional: health check configuration
      tcp: 127.0.0.1:443                # Required if health_check specified
      timeout: 5s                       # Optional: timeout (default: 5s)

    # File ownership (Unix systems)
    owner: nginx                        # Optional: file owner user
    group: ssl-cert                     # Optional: file owner group

  # Combined certificate and key file example
  - name: combined-file
    role: database
    common_name: db.internal.com
    certificate: /etc/mysql/ssl/db.pem  # Same path for both
    key: /etc/mysql/ssl/db.pem          # Creates combined PEM file
    ttl: 360h
    owner: mysql
    group: mysql
```

### Directory Configuration

Load multiple configuration files from a directory:

```bash
# Directory structure
/etc/vault-cert-manager/
├── config.yaml        # Primary config with vault/prometheus/logging
└── conf.d/
    ├── consul.yml     # Consul certificates
    └── nomad.yml      # Nomad certificates
```

Run with directory:
```bash
./vault-cert-manager --config /etc/vault-cert-manager/conf.d/
```

## REST API

Each instance exposes a REST API for status and control:

### Status Endpoints

```bash
# Get certificate status (JSON)
curl http://localhost:9101/api/status

# Web dashboard
open http://localhost:9101/
```

The `/api/status` endpoint returns JSON with certificate details:

```json
[
  {
    "name": "consul-client",
    "common_name": "client.dc1.consul",
    "not_after": "2025-02-24T10:30:00Z",
    "days_left": 30,
    "fingerprint": "abc123...",
    "memory_fingerprint": "abc123...",
    "out_of_sync": false,
    "last_renewed": "2025-01-24T10:30:00Z",
    "status": "healthy"
  }
]
```

The `memory_fingerprint` and `out_of_sync` fields are only populated when a `health_check` is configured for the certificate.

### Rotation Endpoints

```bash
# Rotate a specific certificate
curl -X POST http://localhost:9101/api/rotate/consul-client

# Rotate all certificates
curl -X POST http://localhost:9101/api/rotate/all
```

### Aggregator API

When running in aggregator mode:

```bash
# Get status from all nodes
curl http://localhost:9102/api/status

# Rotate cert on specific node
curl -X POST http://localhost:9102/api/rotate/{node-name}/{cert-name}

# Rotate all certs on specific node
curl -X POST http://localhost:9102/api/rotate/{node-name}/all
```

## Signal Handling

- **SIGHUP**: Force immediate rotation of all certificates
- **SIGINT/SIGTERM**: Graceful shutdown

Example:
```bash
# Trigger rotation via signal
kill -HUP $(pidof vault-cert-manager)
```

## Metrics

Prometheus metrics available at `/metrics`:

- `managed_cert_last_renewed_timestamp_seconds`: Last renewal timestamp
- `managed_cert_not_before_timestamp_seconds`: Certificate not-before time
- `managed_cert_not_after_timestamp_seconds`: Certificate not-after time
- `managed_cert_renewals_total{status}`: Total renewals by status
- `managed_cert_fingerprint_info{fingerprint,location}`: Certificate fingerprints

## Consul Service Registration

For aggregator mode to work, each instance should register with Consul. Example service definition:

```json
{
  "service": {
    "name": "vault-cert-manager",
    "port": 9101,
    "check": {
      "http": "http://localhost:9101/api/status",
      "interval": "30s"
    }
  }
}
```

## Development

```bash
make build         # Build for current platform
make test          # Run tests
make lint          # Run linting
make build-deb     # Build Debian package (amd64)
make build-deb-arm64  # Build Debian package (arm64)
```

## Requirements

- Go 1.23+
- HashiCorp Vault with PKI secrets engine
- Appropriate file system permissions for certificate paths
- (Optional) Consul for aggregator service discovery
