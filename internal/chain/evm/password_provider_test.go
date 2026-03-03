package evm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// EnvPasswordProvider
// ─────────────────────────────────────────────────────────────────────────────

func TestEnvPasswordProvider_New(t *testing.T) {
	p, err := NewEnvPasswordProvider()
	require.NoError(t, err)
	assert.NotNil(t, p)
}

func TestEnvPasswordProvider_GetPassword_Success(t *testing.T) {
	p, _ := NewEnvPasswordProvider()

	envKey := "TEST_KEYSTORE_PASS_ABC"
	os.Setenv(envKey, "my_secret_password")
	defer os.Unsetenv(envKey)

	password, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: envKey})
	require.NoError(t, err)
	assert.Equal(t, []byte("my_secret_password"), password)
}

func TestEnvPasswordProvider_GetPassword_EmptyEnvVar(t *testing.T) {
	p, _ := NewEnvPasswordProvider()

	envKey := "TEST_KEYSTORE_PASS_EMPTY"
	os.Setenv(envKey, "")
	defer os.Unsetenv(envKey)

	_, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: envKey})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
}

func TestEnvPasswordProvider_GetPassword_NoEnvConfigured(t *testing.T) {
	p, _ := NewEnvPasswordProvider()

	_, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password_env not configured")
}

func TestEnvPasswordProvider_GetPassword_EnvNotSet(t *testing.T) {
	p, _ := NewEnvPasswordProvider()

	// Use an env key that's definitely not set
	envKey := "TEST_KEYSTORE_NONEXISTENT_VAR_XYZ_123456"
	os.Unsetenv(envKey)

	_, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: envKey})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
}

// ─────────────────────────────────────────────────────────────────────────────
// CompositePasswordProvider
// ─────────────────────────────────────────────────────────────────────────────

func TestCompositePasswordProvider_NewWithoutStdin(t *testing.T) {
	// When no stdin keystores, should create successfully without stdin provider
	p, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.env)
	assert.Nil(t, p.stdin)
}

func TestCompositePasswordProvider_GetPassword_Env(t *testing.T) {
	p, _ := NewCompositePasswordProvider(false)

	envKey := "TEST_COMPOSITE_PASS"
	os.Setenv(envKey, "composite_secret")
	defer os.Unsetenv(envKey)

	password, err := p.GetPassword("0xabc", KeystoreConfig{
		PasswordEnv:   envKey,
		PasswordStdin: false,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("composite_secret"), password)
}

func TestCompositePasswordProvider_GetPassword_StdinNotInitialized(t *testing.T) {
	// Create without stdin support
	p, _ := NewCompositePasswordProvider(false)

	// Try to use stdin mode
	_, err := p.GetPassword("0xabc", KeystoreConfig{
		PasswordStdin: true,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stdin password provider not initialized")
}
