# Certificate Manager

HashiCorp Vault PKI Certificate Lifecycle Manager

## Overview

Manages X.509 certificate issuance and renewal from HashiCorp Vault's PKI backend with automated lifecycle management, health monitoring, and Prometheus metrics.

## Quick Start

```bash
# Build
make build

# Run with config
./cert-manager --config examples/config.yaml

# View metrics
curl http://localhost:9090/metrics
```

## Features

- **Automated Certificate Management**: Issues missing certificates, renews before expiration with jitter
- **Health Checks**: TCP-based validation comparing disk vs in-memory certificates  
- **Prometheus Metrics**: Comprehensive metrics for monitoring certificate lifecycle
- **Flexible Configuration**: YAML-based config supporting multiple certificates
- **Script Integration**: Optional post-change script execution for service reloads

## Configuration

```yaml
vault:
  address: https://vault.example.com
  token: s.token

prometheus:
  port: 9090
  refresh_interval: 30s

certificates:
  - name: web-cert
    role: web-server
    common_name: www.example.com
    certificate: /etc/ssl/web.crt
    key: /etc/ssl/web.key
    ttl: 30d
    on_change: systemctl reload nginx
    health_check:
      tcp: 127.0.0.1:443
      timeout: 5s
```

## Commands

```bash
# Multiple configs
./cert-manager -c config1.yaml -c config2.yaml

# Show version
./cert-manager --version

# Show help
./cert-manager --help
```

## Metrics

- `managed_cert_last_renewed_timestamp_seconds`: Last renewal timestamp
- `managed_cert_not_before_timestamp_seconds`: Certificate not-before time
- `managed_cert_not_after_timestamp_seconds`: Certificate not-after time  
- `managed_cert_renewals_total{status}`: Total renewals by status
- `managed_cert_fingerprint_info{fingerprint,location}`: Certificate fingerprints

## Development

```bash
make test          # Run tests
make lint          # Run linting  
make check         # All quality checks
make build-all     # Multi-platform build
```

## Requirements

- Go 1.25+
- HashiCorp Vault with PKI backend
- Appropriate file system permissions for certificate paths