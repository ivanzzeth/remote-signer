package config

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// isHexPublicKey
// ---------------------------------------------------------------------------

func TestIsHexPublicKey_Valid64CharHex(t *testing.T) {
	key := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	assert.True(t, isHexPublicKey(key))
}

func TestIsHexPublicKey_WrongLength(t *testing.T) {
	assert.False(t, isHexPublicKey("abcdef"))
}

func TestIsHexPublicKey_NonHexChars(t *testing.T) {
	// 64 chars but contains 'g'
	key := "gbcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	assert.False(t, isHexPublicKey(key))
}

func TestIsHexPublicKey_Empty(t *testing.T) {
	assert.False(t, isHexPublicKey(""))
}

func TestIsHexPublicKey_UppercaseHex(t *testing.T) {
	key := "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	assert.True(t, isHexPublicKey(key))
}

func TestIsHexPublicKey_MixedCase(t *testing.T) {
	key := "AbCdEf0123456789aBcDeF0123456789AbCdEf0123456789aBcDeF0123456789"
	assert.True(t, isHexPublicKey(key))
}

// ---------------------------------------------------------------------------
// ExpandEnvWithDefaults
// ---------------------------------------------------------------------------

func TestExpandEnvWithDefaults_BracedVarSet(t *testing.T) {
	t.Setenv("TEST_EXPAND_VAR", "hello")
	result := ExpandEnvWithDefaults("prefix-${TEST_EXPAND_VAR}-suffix")
	assert.Equal(t, "prefix-hello-suffix", result)
}

func TestExpandEnvWithDefaults_BracedVarNotSet(t *testing.T) {
	os.Unsetenv("TEST_EXPAND_UNSET_VAR")
	result := ExpandEnvWithDefaults("prefix-${TEST_EXPAND_UNSET_VAR}-suffix")
	assert.Equal(t, "prefix--suffix", result)
}

func TestExpandEnvWithDefaults_BracedVarWithDefaultSet(t *testing.T) {
	t.Setenv("TEST_EXPAND_DEF_VAR", "actual")
	result := ExpandEnvWithDefaults("${TEST_EXPAND_DEF_VAR:-fallback}")
	assert.Equal(t, "actual", result)
}

func TestExpandEnvWithDefaults_BracedVarWithDefaultNotSet(t *testing.T) {
	os.Unsetenv("TEST_EXPAND_DEF_MISS")
	result := ExpandEnvWithDefaults("${TEST_EXPAND_DEF_MISS:-fallback}")
	assert.Equal(t, "fallback", result)
}

func TestExpandEnvWithDefaults_MultipleSubstitutions(t *testing.T) {
	t.Setenv("TEST_A", "alpha")
	t.Setenv("TEST_B", "beta")
	result := ExpandEnvWithDefaults("${TEST_A}-${TEST_B}")
	assert.Equal(t, "alpha-beta", result)
}

func TestExpandEnvWithDefaults_NoSubstitutions(t *testing.T) {
	result := ExpandEnvWithDefaults("plain string with no vars")
	assert.Equal(t, "plain string with no vars", result)
}

func TestExpandEnvWithDefaults_SimpleVarSet(t *testing.T) {
	t.Setenv("TEST_SIMPLE", "simple_val")
	result := ExpandEnvWithDefaults("value=$TEST_SIMPLE end")
	assert.Contains(t, result, "simple_val")
}

func TestExpandEnvWithDefaults_SimpleVarNotSet(t *testing.T) {
	os.Unsetenv("TEST_SIMPLE_MISS")
	result := ExpandEnvWithDefaults("value=$TEST_SIMPLE_MISS end")
	assert.Equal(t, "value= end", result)
}

// ---------------------------------------------------------------------------
// APIKeyConfig.ResolvePublicKey
// ---------------------------------------------------------------------------

func TestResolvePublicKey_DirectHex(t *testing.T) {
	hexKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	cfg := APIKeyConfig{ID: "test", PublicKey: hexKey}
	result, err := cfg.ResolvePublicKey()
	require.NoError(t, err)
	assert.Equal(t, hexKey, result)
}

func TestResolvePublicKey_DirectBase64DER(t *testing.T) {
	// Build a 44-byte DER blob: 12-byte header + 32-byte key
	header := make([]byte, 12)
	pubBytes := make([]byte, 32)
	for i := range pubBytes {
		pubBytes[i] = byte(i)
	}
	der := append(header, pubBytes...)
	b64 := base64.StdEncoding.EncodeToString(der)

	cfg := APIKeyConfig{ID: "test", PublicKey: b64}
	result, err := cfg.ResolvePublicKey()
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(pubBytes), result)
}

func TestResolvePublicKey_FromEnvHex(t *testing.T) {
	hexKey := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	t.Setenv("TEST_PK_ENV", hexKey)
	cfg := APIKeyConfig{ID: "test", PublicKeyEnv: "TEST_PK_ENV"}
	result, err := cfg.ResolvePublicKey()
	require.NoError(t, err)
	assert.Equal(t, hexKey, result)
}

func TestResolvePublicKey_EmptyEnvVar(t *testing.T) {
	t.Setenv("TEST_PK_EMPTY", "")
	cfg := APIKeyConfig{ID: "test", PublicKeyEnv: "TEST_PK_EMPTY"}
	_, err := cfg.ResolvePublicKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestResolvePublicKey_NeitherKeyNorEnv(t *testing.T) {
	cfg := APIKeyConfig{ID: "test"}
	_, err := cfg.ResolvePublicKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no public_key or public_key_env")
}

func TestResolvePublicKey_InvalidBase64(t *testing.T) {
	cfg := APIKeyConfig{ID: "test", PublicKey: "not-valid-base64!!!"}
	_, err := cfg.ResolvePublicKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid hex or base64")
}

func TestResolvePublicKey_TooShortBase64DER(t *testing.T) {
	// Only 16 bytes, less than 32
	short := make([]byte, 16)
	b64 := base64.StdEncoding.EncodeToString(short)
	cfg := APIKeyConfig{ID: "test", PublicKey: b64}
	_, err := cfg.ResolvePublicKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key length")
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

func validConfig() *Config {
	return &Config{
		Server:   ServerConfig{Port: 8080},
		Database: storage.Config{DSN: "test"},
		Chains:   ChainsConfig{EVM: &EVMConfig{Enabled: true}},
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	err := validate(validConfig())
	assert.NoError(t, err)
}

func TestValidate_InvalidPortZero(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Port = 0
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid server port")
}

func TestValidate_InvalidPortTooHigh(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Port = 70000
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid server port")
}

func TestValidate_EmptyDatabaseDSN(t *testing.T) {
	cfg := validConfig()
	cfg.Database.DSN = ""
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database DSN is required")
}

func TestValidate_NoChainEnabled(t *testing.T) {
	cfg := validConfig()
	cfg.Chains.EVM = nil
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain must be enabled")
}

func TestValidate_EVMDisabled(t *testing.T) {
	cfg := validConfig()
	cfg.Chains.EVM.Enabled = false
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain must be enabled")
}

func TestValidate_TLSEnabledWithoutCert(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.KeyFile = "/some/key"
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_file is not set")
}

func TestValidate_TLSEnabledWithoutKey(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "/some/cert"
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key_file is not set")
}

func TestValidate_TLSWithNonExistentCertFile(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "/nonexistent/cert.pem"
	cfg.Server.TLS.KeyFile = "/nonexistent/key.pem"
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS cert_file not found")
}

func TestValidate_TLSWithNonExistentKeyFile(t *testing.T) {
	// cert file exists, key file does not
	certFile, err := os.CreateTemp("", "cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(certFile.Name())
	certFile.Close()

	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = certFile.Name()
	cfg.Server.TLS.KeyFile = "/nonexistent/key.pem"
	err = validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS key_file not found")
}

func TestValidate_TLSValid(t *testing.T) {
	certFile, err := os.CreateTemp("", "cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(certFile.Name())
	certFile.Close()

	keyFile, err := os.CreateTemp("", "key-*.pem")
	require.NoError(t, err)
	defer os.Remove(keyFile.Name())
	keyFile.Close()

	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = certFile.Name()
	cfg.Server.TLS.KeyFile = keyFile.Name()
	err = validate(cfg)
	assert.NoError(t, err)
}

func TestValidate_MTLSWithoutCAFile(t *testing.T) {
	certFile, err := os.CreateTemp("", "cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(certFile.Name())
	certFile.Close()

	keyFile, err := os.CreateTemp("", "key-*.pem")
	require.NoError(t, err)
	defer os.Remove(keyFile.Name())
	keyFile.Close()

	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = certFile.Name()
	cfg.Server.TLS.KeyFile = keyFile.Name()
	cfg.Server.TLS.ClientAuth = true
	cfg.Server.TLS.CAFile = ""
	err = validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_file is not set")
}

func TestValidate_MTLSWithNonExistentCAFile(t *testing.T) {
	certFile, err := os.CreateTemp("", "cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(certFile.Name())
	certFile.Close()

	keyFile, err := os.CreateTemp("", "key-*.pem")
	require.NoError(t, err)
	defer os.Remove(keyFile.Name())
	keyFile.Close()

	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = certFile.Name()
	cfg.Server.TLS.KeyFile = keyFile.Name()
	cfg.Server.TLS.ClientAuth = true
	cfg.Server.TLS.CAFile = "/nonexistent/ca.pem"
	err = validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS ca_file not found")
}

func TestValidate_DuplicateAPIKeyIDs(t *testing.T) {
	cfg := validConfig()
	cfg.APIKeys = []APIKeyConfig{
		{ID: "key1", Enabled: false},
		{ID: "key1", Enabled: false},
	}
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate id")
}

func TestValidate_APIKeyWithoutID(t *testing.T) {
	cfg := validConfig()
	cfg.APIKeys = []APIKeyConfig{
		{ID: "", Enabled: true},
	}
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id is required")
}

func TestValidate_EnabledAPIKeyWithoutPublicKey(t *testing.T) {
	cfg := validConfig()
	cfg.APIKeys = []APIKeyConfig{
		{ID: "key1", Enabled: true},
	}
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public_key or public_key_env is required")
}

func TestValidate_DisabledAPIKeyWithoutPublicKey(t *testing.T) {
	cfg := validConfig()
	cfg.APIKeys = []APIKeyConfig{
		{ID: "key1", Enabled: false},
	}
	err := validate(cfg)
	assert.NoError(t, err)
}

func TestValidate_AdminAndAgentMutuallyExclusive(t *testing.T) {
	cfg := validConfig()
	cfg.APIKeys = []APIKeyConfig{
		{ID: "key1", Enabled: true, PublicKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Admin: true, Agent: true},
	}
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin and agent are mutually exclusive")
}

func TestValidate_AgentKeyOnly(t *testing.T) {
	cfg := validConfig()
	cfg.APIKeys = []APIKeyConfig{
		{ID: "key1", Enabled: true, PublicKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Agent: true},
	}
	err := validate(cfg)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// setDefaults
// ---------------------------------------------------------------------------

func TestSetDefaults_EmptyHost(t *testing.T) {
	cfg := &Config{}
	setDefaults(cfg)
	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
}

func TestSetDefaults_ZeroMaxRequestAge(t *testing.T) {
	cfg := &Config{}
	setDefaults(cfg)
	assert.Equal(t, 60*time.Second, cfg.Security.MaxRequestAge)
}

func TestSetDefaults_ZeroRateLimitDefault(t *testing.T) {
	cfg := &Config{}
	setDefaults(cfg)
	assert.Equal(t, 100, cfg.Security.RateLimitDefault)
}

func TestSetDefaults_NilNonceRequired(t *testing.T) {
	cfg := &Config{}
	setDefaults(cfg)
	require.NotNil(t, cfg.Security.NonceRequired)
	assert.True(t, *cfg.Security.NonceRequired)
}

func TestSetDefaults_EmptyLoggerLevel(t *testing.T) {
	cfg := &Config{}
	setDefaults(cfg)
	assert.Equal(t, "info", cfg.Logger.Level)
}

func TestSetDefaults_ApprovalGuardEnabledZeroThreshold(t *testing.T) {
	cfg := &Config{}
	cfg.Security.ApprovalGuard.Enabled = true
	setDefaults(cfg)
	assert.Equal(t, 10, cfg.Security.ApprovalGuard.Threshold)
}

func TestSetDefaults_ApprovalGuardEnabledZeroWindow(t *testing.T) {
	cfg := &Config{}
	cfg.Security.ApprovalGuard.Enabled = true
	setDefaults(cfg)
	assert.Equal(t, 5*time.Minute, cfg.Security.ApprovalGuard.Window)
}

func TestSetDefaults_ApprovalGuardEnabledZeroResume(t *testing.T) {
	cfg := &Config{}
	cfg.Security.ApprovalGuard.Enabled = true
	setDefaults(cfg)
	assert.Equal(t, 2*time.Hour, cfg.Security.ApprovalGuard.ResumeAfter)
}

func TestSetDefaults_PreservesExistingValues(t *testing.T) {
	nonceReq := false
	cfg := &Config{
		Server: ServerConfig{Host: "0.0.0.0"},
		Security: SecurityConfig{
			MaxRequestAge:    30 * time.Second,
			RateLimitDefault: 50,
			NonceRequired:    &nonceReq,
		},
		Logger: LoggerConfig{Level: "debug"},
	}
	setDefaults(cfg)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 30*time.Second, cfg.Security.MaxRequestAge)
	assert.Equal(t, 50, cfg.Security.RateLimitDefault)
	assert.False(t, *cfg.Security.NonceRequired)
	assert.Equal(t, "debug", cfg.Logger.Level)
}

func TestSecurityConfig_IsSIGHUPRulesReloadEnabled_DefaultFalse(t *testing.T) {
	var s SecurityConfig
	assert.False(t, s.IsSIGHUPRulesReloadEnabled())
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

func TestLoad_EmptyPath(t *testing.T) {
	_, err := Load("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config path is required")
}

func TestLoad_NonExistentPath(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yamlContent := `
server:
  host: "0.0.0.0"
  port: 9090
database:
  dsn: "file:test.db"
chains:
  evm:
    enabled: true
logger:
  level: "debug"
`
	err := os.WriteFile(cfgPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, "file:test.db", cfg.Database.DSN)
	assert.True(t, cfg.Chains.EVM.Enabled)
	assert.Equal(t, "debug", cfg.Logger.Level)
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")

	err := os.WriteFile(cfgPath, []byte("{{invalid yaml content"), 0644)
	require.NoError(t, err)

	_, err = Load(cfgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestLoad_ValidationFailure(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	// Valid YAML but fails validation (port = 0)
	yamlContent := `
server:
  port: 0
database:
  dsn: "file:test.db"
chains:
  evm:
    enabled: true
`
	err := os.WriteFile(cfgPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	_, err = Load(cfgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config validation failed")
}

func TestLoad_ExpandsEnvVars(t *testing.T) {
	t.Setenv("TEST_LOAD_DSN", "file:env.db")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yamlContent := `
server:
  port: 8080
database:
  dsn: "${TEST_LOAD_DSN}"
chains:
  evm:
    enabled: true
`
	err := os.WriteFile(cfgPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "file:env.db", cfg.Database.DSN)
}

func TestLoad_SetsDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yamlContent := `
server:
  port: 8080
database:
  dsn: "file:test.db"
chains:
  evm:
    enabled: true
`
	err := os.WriteFile(cfgPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	// Defaults should be applied
	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 60*time.Second, cfg.Security.MaxRequestAge)
	assert.Equal(t, 100, cfg.Security.RateLimitDefault)
	require.NotNil(t, cfg.Security.NonceRequired)
	assert.True(t, *cfg.Security.NonceRequired)
	assert.Equal(t, "info", cfg.Logger.Level)
}
