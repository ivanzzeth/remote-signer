package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// Config is the root configuration structure
type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Database      storage.Config      `yaml:"database"`
	Chains        ChainsConfig        `yaml:"chains"`
	Notify        notify.Config       `yaml:"notify"`
	NotifyChannel notify.Channel      `yaml:"notify_channels"`
	Security      SecurityConfig      `yaml:"security"`
	Logger        LoggerConfig        `yaml:"logger"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host string    `yaml:"host"`
	Port int       `yaml:"port"`
	TLS  TLSConfig `yaml:"tls"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// ChainsConfig contains chain-specific configurations
type ChainsConfig struct {
	EVM *EVMConfig `yaml:"evm,omitempty"`
}

// EVMConfig contains EVM chain configuration
type EVMConfig struct {
	Enabled bool              `yaml:"enabled"`
	Signers evm.SignerConfig  `yaml:"signers"`
	Foundry FoundryConfig     `yaml:"foundry"`
}

// FoundryConfig contains Foundry (forge) configuration for Solidity rules
type FoundryConfig struct {
	Enabled   bool          `yaml:"enabled"`
	ForgePath string        `yaml:"forge_path"` // path to forge binary, empty = auto-detect from PATH
	CacheDir  string        `yaml:"cache_dir"`  // cache directory for compiled scripts
	Timeout   time.Duration `yaml:"timeout"`    // max execution time per rule (default: 30s)
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	MaxRequestAge    time.Duration `yaml:"max_request_age"`
	RateLimitDefault int           `yaml:"rate_limit_default"`
}

// LoggerConfig contains logging configuration
type LoggerConfig struct {
	Level  string `yaml:"level"` // debug, info, warn, error
	Pretty bool   `yaml:"pretty"`
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in the config
	expandedData := os.ExpandEnv(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expandedData), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Set defaults
	setDefaults(cfg)

	return cfg, nil
}

// validate validates the configuration
func validate(cfg *Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}

	if cfg.Server.TLS.Enabled {
		if cfg.Server.TLS.CertFile == "" {
			return fmt.Errorf("TLS cert_file is required when TLS is enabled")
		}
		if cfg.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS key_file is required when TLS is enabled")
		}
	}

	if cfg.Database.DSN == "" {
		return fmt.Errorf("database DSN is required")
	}

	// Validate at least one chain is enabled
	if cfg.Chains.EVM == nil || !cfg.Chains.EVM.Enabled {
		return fmt.Errorf("at least one chain must be enabled")
	}

	return nil
}

// setDefaults sets default values for configuration
func setDefaults(cfg *Config) {
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}

	if cfg.Security.MaxRequestAge == 0 {
		cfg.Security.MaxRequestAge = 5 * time.Minute
	}

	if cfg.Security.RateLimitDefault <= 0 {
		cfg.Security.RateLimitDefault = 100
	}

	if cfg.Logger.Level == "" {
		cfg.Logger.Level = "info"
	}
}
