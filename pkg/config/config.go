package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Vault        VaultConfig        `yaml:"vault"`
	Prometheus   PrometheusConfig   `yaml:"prometheus"`
	Certificates []CertificateConfig `yaml:"certificates"`
}

type VaultConfig struct {
	Address string `yaml:"address"`
	Token   string `yaml:"token"`
}

type PrometheusConfig struct {
	Port            int           `yaml:"port"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
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

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", filename, err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

func validateConfig(config *Config) error {
	if config.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}
	if config.Vault.Token == "" {
		return fmt.Errorf("vault.token is required")
	}

	if config.Prometheus.Port == 0 {
		config.Prometheus.Port = 9090
	}
	if config.Prometheus.RefreshInterval == 0 {
		config.Prometheus.RefreshInterval = 10 * time.Second
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

func (c *CertificateConfig) IsCombinedFile() bool {
	return c.Certificate == c.Key
}