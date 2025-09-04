package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Vault        VaultConfig        `yaml:"vault"`
	Prometheus   PrometheusConfig   `yaml:"prometheus"`
	Logging      LoggingConfig      `yaml:"logging"`
	Certificates []CertificateConfig `yaml:"certificates"`
}

type VaultConfig struct {
	Address string     `yaml:"address"`
	Auth    AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	Token *TokenAuth `yaml:"token,omitempty"`
	GCP   *GCPAuth   `yaml:"gcp,omitempty"`
	TLS   *TLSAuth   `yaml:"tls,omitempty"`
}

type TokenAuth struct {
	Value string `yaml:"value"`
}

type GCPAuth struct {
	MountPath       string `yaml:"mount_path,omitempty"`
	Role            string `yaml:"role"`
	Type            string `yaml:"type"` // "iam" or "gce"
	ServiceAccount  string `yaml:"service_account,omitempty"`
	JWTExp          string `yaml:"jwt_exp,omitempty"`
	CredentialsFile string `yaml:"credentials_file,omitempty"`
}

type TLSAuth struct {
	MountPath string `yaml:"mount_path,omitempty"`
	CertFile  string `yaml:"cert_file"`
	KeyFile   string `yaml:"key_file"`
	Name      string `yaml:"name,omitempty"`
}

type PrometheusConfig struct {
	Port            int           `yaml:"port"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type CertificateConfig struct {
	Name         string        `yaml:"name"`
	Role         string        `yaml:"role"`
	CommonName   string        `yaml:"common_name"`
	Certificate  string        `yaml:"certificate"`
	Key          string        `yaml:"key"`
	TTL          time.Duration `yaml:"ttl"`
	AltNames     []string      `yaml:"alt_names,omitempty"`
	IPSans       []string      `yaml:"ip_sans,omitempty"`
	OnChange     string        `yaml:"on_change,omitempty"`
	HealthCheck  *HealthCheck  `yaml:"health_check,omitempty"`
	Owner        string        `yaml:"owner,omitempty"`
	Group        string        `yaml:"group,omitempty"`
}

type HealthCheck struct {
	TCP     string        `yaml:"tcp,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	var configs []*Config
	
	if stat.IsDir() {
		dirConfigs, err := loadConfigFromDirectory(path)
		if err != nil {
			return nil, err
		}
		configs = dirConfigs
	} else {
		config, err := loadConfigFromFile(path)
		if err != nil {
			return nil, err
		}
		configs = []*Config{config}
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("no configuration files found")
	}

	merged := configs[0]
	for i := 1; i < len(configs); i++ {
		merged.Certificates = append(merged.Certificates, configs[i].Certificates...)
	}

	if err := validateConfig(merged); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return merged, nil
}

func loadConfigFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", filename, err)
	}

	return &config, nil
}

func loadConfigFromDirectory(dir string) ([]*Config, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var configs []*Config
	var primaryConfig *Config

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if !strings.HasSuffix(filename, ".yml") && !strings.HasSuffix(filename, ".yaml") {
			continue
		}

		fullPath := filepath.Join(dir, filename)
		config, err := loadConfigFromFile(fullPath)
		if err != nil {
			return nil, err
		}

		if primaryConfig == nil && (config.Vault.Address != "" || hasAuthConfig(&config.Vault.Auth)) {
			primaryConfig = config
		} else {
			configs = append(configs, config)
		}
	}

	if primaryConfig != nil {
		configs = append([]*Config{primaryConfig}, configs...)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("no .yml or .yaml files found in directory %s", dir)
	}

	return configs, nil
}

func validateConfig(config *Config) error {
	if config.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}
	
	if err := validateAuthConfig(&config.Vault.Auth); err != nil {
		return fmt.Errorf("vault.auth: %w", err)
	}

	if config.Prometheus.Port == 0 {
		config.Prometheus.Port = 9090
	}
	if config.Prometheus.RefreshInterval == 0 {
		config.Prometheus.RefreshInterval = 10 * time.Second
	}

	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "text"
	}

	if config.Logging.Format != "json" && config.Logging.Format != "text" {
		return fmt.Errorf("logging.format must be 'json' or 'text', got '%s'", config.Logging.Format)
	}

	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLevels[config.Logging.Level] {
		return fmt.Errorf("logging.level must be one of 'debug', 'info', 'warn', 'error', got '%s'", config.Logging.Level)
	}

	certNames := make(map[string]bool)
	for i, cert := range config.Certificates {
		if cert.Name == "" {
			return fmt.Errorf("certificates[%d].name is required", i)
		}
		if certNames[cert.Name] {
			return fmt.Errorf("duplicate certificate name: %s", cert.Name)
		}
		certNames[cert.Name] = true

		if cert.Role == "" {
			return fmt.Errorf("certificates[%d].role is required for %s", i, cert.Name)
		}
		if cert.CommonName == "" {
			return fmt.Errorf("certificates[%d].common_name is required for %s", i, cert.Name)
		}
		if cert.Certificate == "" {
			return fmt.Errorf("certificates[%d].certificate is required for %s", i, cert.Name)
		}
		if cert.Key == "" {
			return fmt.Errorf("certificates[%d].key is required for %s", i, cert.Name)
		}

		if cert.TTL == 0 {
			config.Certificates[i].TTL = 24 * time.Hour
		}

		if cert.HealthCheck != nil {
			if cert.HealthCheck.TCP == "" {
				return fmt.Errorf("certificates[%d].health_check.tcp is required when health_check is specified for %s", i, cert.Name)
			}
			if cert.HealthCheck.Timeout == 0 {
				config.Certificates[i].HealthCheck.Timeout = 5 * time.Second
			}
		}
	}

	return nil
}

func validateAuthConfig(auth *AuthConfig) error {
	authMethods := 0
	
	if auth.Token != nil {
		authMethods++
		if auth.Token.Value == "" {
			return fmt.Errorf("token.value is required")
		}
	}
	
	if auth.GCP != nil {
		authMethods++
		if auth.GCP.Role == "" {
			return fmt.Errorf("gcp.role is required")
		}
		if auth.GCP.Type == "" {
			return fmt.Errorf("gcp.type is required (must be 'iam' or 'gce')")
		}
		if auth.GCP.Type != "iam" && auth.GCP.Type != "gce" {
			return fmt.Errorf("gcp.type must be 'iam' or 'gce', got '%s'", auth.GCP.Type)
		}
		if auth.GCP.MountPath == "" {
			auth.GCP.MountPath = "gcp"
		}
	}
	
	if auth.TLS != nil {
		authMethods++
		if auth.TLS.CertFile == "" {
			return fmt.Errorf("tls.cert_file is required")
		}
		if auth.TLS.KeyFile == "" {
			return fmt.Errorf("tls.key_file is required")
		}
		if auth.TLS.MountPath == "" {
			auth.TLS.MountPath = "cert"
		}
	}
	
	if authMethods == 0 {
		return fmt.Errorf("exactly one authentication method must be specified (token, gcp, or tls)")
	}
	if authMethods > 1 {
		return fmt.Errorf("only one authentication method can be specified, found %d", authMethods)
	}
	
	return nil
}

func hasAuthConfig(auth *AuthConfig) bool {
	return auth.Token != nil || auth.GCP != nil || auth.TLS != nil
}

func (c *CertificateConfig) IsCombinedFile() bool {
	return c.Certificate == c.Key
}