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
- **Flexible Configuration**: YAML-based config supporting multiple certificates and directories
- **Script Integration**: Optional post-change script execution for service reloads
- **Certificate Chains**: Automatic inclusion of intermediate certificates in output files
- **Structured Logging**: JSON or text format with configurable log levels

## Configuration

### Basic Configuration

```yaml
vault:
  address: https://vault.example.com    # Required: Vault server URL
  auth:
    token:
      value: s.token                    # Required: Vault token

prometheus:
  port: 9090                            # Optional: metrics port (default: 9090)
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
    ttl: 720h                          # Optional: certificate lifetime (default: 24h)
    on_change: systemctl reload nginx   # Optional: command to run after renewal
    health_check:                       # Optional: health check configuration
      tcp: 127.0.0.1:443                # Required if health_check specified
      timeout: 5s                       # Optional: check timeout (default: 5s)
```

### Authentication Methods

#### Token Authentication (Default)
```yaml
vault:
  address: https://vault.example.com
  auth:
    token:
      value: s.hvs.your-vault-token
```

#### GCP Authentication
```yaml
vault:
  address: https://vault.example.com
  auth:
    gcp:
      role: your-gcp-role              # Required: GCP auth role in Vault
      type: gce                        # Required: "gce" or "iam"
      mount_path: gcp                  # Optional: auth mount path (default: "gcp")
      
      # For IAM type only:
      service_account: vault@project.iam.gserviceaccount.com  # Required for IAM
      jwt_exp: 15m                     # Optional: JWT expiration (default: 15m)
      credentials_file: /path/to/sa.json  # Optional: service account key file
```

#### TLS Certificate Authentication
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
    key: /etc/ssl/key.pem              # Required: private key output path
    ttl: 720h                          # Optional: certificate lifetime (default: 24h)
    
    # Subject Alternative Names
    alt_names:                          # Optional: DNS alternative names
      - www.example.com
      - api.example.com
      - example.com
    ip_sans:                           # Optional: IP alternative names
      - 192.168.1.100
      - 10.0.0.1
    
    # Post-renewal actions
    on_change: "systemctl reload nginx" # Optional: command to execute after renewal
    
    # Health monitoring
    health_check:                       # Optional: health check configuration
      tcp: 127.0.0.1:443               # Required if health_check specified
      timeout: 5s                       # Optional: timeout (default: 5s)
    
    # File ownership (Unix systems)
    owner: nginx                        # Optional: file owner user
    group: ssl-cert                     # Optional: file owner group

  # Combined certificate and key file example
  - name: combined-file
    role: database
    common_name: db.internal.com
    certificate: /etc/mysql/ssl/db.pem  # Same path for both cert and key
    key: /etc/mysql/ssl/db.pem         # creates combined PEM file
    ttl: 360h
    owner: mysql
    group: mysql
```

### Directory Configuration

Load multiple configuration files from a directory:

```bash
# Directory structure
/etc/cert-manager/
├── vault.yml          # Primary config with vault/prometheus/logging
├── web-certs.yml      # Web server certificates
└── db-certs.yml       # Database certificates
```

**vault.yml:**
```yaml
vault:
  address: https://vault.company.local
  auth:
    token:
      value: s.hvs.token
prometheus:
  port: 9090
logging:
  level: info
```

**web-certs.yml:**
```yaml
certificates:
  - name: web1
    role: web-server
    common_name: web1.company.local
    certificate: /etc/ssl/web1.crt
    key: /etc/ssl/web1.key
```

## Commands

```bash
# Single config file
./cert-manager --config config.yaml

# Directory with multiple .yml files
./cert-manager --config /etc/cert-manager/conf.d/

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