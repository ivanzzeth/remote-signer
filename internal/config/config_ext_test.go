package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestIsAPIKeysAPIReadonly
// ---------------------------------------------------------------------------

func TestIsAPIKeysAPIReadonly(t *testing.T) {
	t.Run("defaults to false when nil", func(t *testing.T) {
		sc := SecurityConfig{APIKeysAPIReadonly: nil}
		assert.False(t, sc.IsAPIKeysAPIReadonly())
	})

	t.Run("returns true when set to true", func(t *testing.T) {
		sc := SecurityConfig{APIKeysAPIReadonly: boolPtr(true)}
		assert.True(t, sc.IsAPIKeysAPIReadonly())
	})

	t.Run("returns false when set to false", func(t *testing.T) {
		sc := SecurityConfig{APIKeysAPIReadonly: boolPtr(false)}
		assert.False(t, sc.IsAPIKeysAPIReadonly())
	})
}

// ---------------------------------------------------------------------------
// TestLoadUnvalidated
// ---------------------------------------------------------------------------

func TestLoadUnvalidated(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		_, err := LoadUnvalidated("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config path is required")
	})

	t.Run("non-existent path", func(t *testing.T) {
		_, err := LoadUnvalidated("/nonexistent/path/config.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("minimal valid config", func(t *testing.T) {
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
		require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))
		cfg, err := LoadUnvalidated(cfgPath)
		require.NoError(t, err)
		assert.Equal(t, 8080, cfg.Server.Port)
	})

	t.Run("applies defaults", func(t *testing.T) {
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
		require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))
		cfg, err := LoadUnvalidated(cfgPath)
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	})

	t.Run("rejects invalid config", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.yaml")
		yamlContent := `
server:
  port: 0
database:
  dsn: "file:test.db"
chains:
  evm:
    enabled: true
`
		require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))
		_, err := LoadUnvalidated(cfgPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid server port")
	})

	t.Run("parses env vars", func(t *testing.T) {
		t.Setenv("TEST_DB_DSN", "file:env.db")
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.yaml")
		yamlContent := `
server:
  port: 8080
database:
  dsn: "${TEST_DB_DSN}"
chains:
  evm:
    enabled: true
`
		require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))
		cfg, err := LoadUnvalidated(cfgPath)
		require.NoError(t, err)
		assert.Equal(t, "file:env.db", cfg.Database.DSN)
	})

	t.Run("invalid YAML", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "bad.yaml")
		require.NoError(t, os.WriteFile(cfgPath, []byte("{{invalid"), 0644))
		_, err := LoadUnvalidated(cfgPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse config file")
	})
}

// ---------------------------------------------------------------------------
// TestSetDefaults - simulation budget defaults
// ---------------------------------------------------------------------------

func TestSetDefaults_SimulationBudgetDefaults(t *testing.T) {
	t.Run("sets all simulation budget defaults", func(t *testing.T) {
		cfg := &Config{
			Chains: ChainsConfig{
				EVM: &EVMConfig{
					Enabled:    true,
					Simulation: SimulationConfig{Enabled: true},
				},
			},
		}
		setDefaults(cfg)
		assert.Equal(t, "0.01", cfg.Chains.EVM.Simulation.BudgetNativeMaxTotal)
		assert.Equal(t, "0.1", cfg.Chains.EVM.Simulation.BudgetNativeMaxPerTx)
		assert.Equal(t, "100", cfg.Chains.EVM.Simulation.BudgetERC20MaxTotal)
		assert.Equal(t, "50", cfg.Chains.EVM.Simulation.BudgetERC20MaxPerTx)
	})

	t.Run("preserves explicit simulation budget values", func(t *testing.T) {
		cfg := &Config{
			Chains: ChainsConfig{
				EVM: &EVMConfig{
					Enabled: true,
					Simulation: SimulationConfig{
						Enabled:              true,
						BudgetNativeMaxTotal: "999",
						BudgetNativeMaxPerTx: "888",
					},
				},
			},
		}
		setDefaults(cfg)
		assert.Equal(t, "999", cfg.Chains.EVM.Simulation.BudgetNativeMaxTotal)
		assert.Equal(t, "888", cfg.Chains.EVM.Simulation.BudgetNativeMaxPerTx)
		assert.Equal(t, "100", cfg.Chains.EVM.Simulation.BudgetERC20MaxTotal) // still default
		assert.Equal(t, "50", cfg.Chains.EVM.Simulation.BudgetERC20MaxPerTx)  // still default
	})

	t.Run("does not set simulation defaults when simulation disabled", func(t *testing.T) {
		cfg := &Config{
			Chains: ChainsConfig{
				EVM: &EVMConfig{
					Enabled:    true,
					Simulation: SimulationConfig{Enabled: false},
				},
			},
		}
		setDefaults(cfg)
		assert.Equal(t, "", cfg.Chains.EVM.Simulation.BudgetNativeMaxTotal)
		assert.Equal(t, "", cfg.Chains.EVM.Simulation.BudgetNativeMaxPerTx)
		assert.Equal(t, "", cfg.Chains.EVM.Simulation.BudgetERC20MaxTotal)
		assert.Equal(t, "", cfg.Chains.EVM.Simulation.BudgetERC20MaxPerTx)
	})

	t.Run("does not set simulation defaults when EVM is nil", func(t *testing.T) {
		cfg := &Config{Chains: ChainsConfig{}}
		setDefaults(cfg)
		// Should not panic
	})

	t.Run("simulation timeout defaults", func(t *testing.T) {
		cfg := &Config{
			Chains: ChainsConfig{
				EVM: &EVMConfig{
					Enabled:    true,
					Simulation: SimulationConfig{Enabled: true},
				},
			},
		}
		setDefaults(cfg)
		assert.Equal(t, 60*time.Second, cfg.Chains.EVM.Simulation.Timeout)
		assert.Equal(t, 1*time.Second, cfg.Chains.EVM.Simulation.BatchWindow)
		assert.Equal(t, 20, cfg.Chains.EVM.Simulation.BatchMaxSize)
	})
}

// ---------------------------------------------------------------------------
// TestSetDefaults - ApprovalGuard defaults
// ---------------------------------------------------------------------------

func TestSetDefaults_ApprovalGuardDefaults(t *testing.T) {
	t.Run("sets all approval guard defaults when enabled", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.ApprovalGuard.Enabled = true
		setDefaults(cfg)
		assert.Equal(t, 1*time.Hour, cfg.Security.ApprovalGuard.Window)
		assert.Equal(t, float64(50), cfg.Security.ApprovalGuard.RejectionThresholdPct)
		assert.Equal(t, 10, cfg.Security.ApprovalGuard.MinSamples)
		assert.Equal(t, 2*time.Hour, cfg.Security.ApprovalGuard.ResumeAfter)
	})

	t.Run("does not set approval guard defaults when disabled", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.ApprovalGuard.Enabled = false
		setDefaults(cfg)
		assert.Equal(t, time.Duration(0), cfg.Security.ApprovalGuard.Window)
		assert.Equal(t, float64(0), cfg.Security.ApprovalGuard.RejectionThresholdPct)
		assert.Equal(t, 0, cfg.Security.ApprovalGuard.MinSamples)
		assert.Equal(t, time.Duration(0), cfg.Security.ApprovalGuard.ResumeAfter)
	})

	t.Run("preserves explicit approval guard values", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.ApprovalGuard.Enabled = true
		cfg.Security.ApprovalGuard.Window = 30 * time.Minute
		cfg.Security.ApprovalGuard.RejectionThresholdPct = 75
		cfg.Security.ApprovalGuard.MinSamples = 20
		cfg.Security.ApprovalGuard.ResumeAfter = 4 * time.Hour
		setDefaults(cfg)
		assert.Equal(t, 30*time.Minute, cfg.Security.ApprovalGuard.Window)
		assert.Equal(t, float64(75), cfg.Security.ApprovalGuard.RejectionThresholdPct)
		assert.Equal(t, 20, cfg.Security.ApprovalGuard.MinSamples)
		assert.Equal(t, 4*time.Hour, cfg.Security.ApprovalGuard.ResumeAfter)
	})
}

// ---------------------------------------------------------------------------
// TestIsSIGHUPRulesReloadEnabled
// ---------------------------------------------------------------------------

func TestIsSIGHUPRulesReloadEnabled(t *testing.T) {
	t.Run("defaults to false when nil", func(t *testing.T) {
		var s SecurityConfig
		assert.False(t, s.IsSIGHUPRulesReloadEnabled())
	})

	t.Run("returns true when set to true", func(t *testing.T) {
		s := SecurityConfig{AllowSIGHUPRulesReload: boolPtr(true)}
		assert.True(t, s.IsSIGHUPRulesReloadEnabled())
	})

	t.Run("returns false when set to false", func(t *testing.T) {
		s := SecurityConfig{AllowSIGHUPRulesReload: boolPtr(false)}
		assert.False(t, s.IsSIGHUPRulesReloadEnabled())
	})
}

// ---------------------------------------------------------------------------
// TestValidate - additional scenarios
// ---------------------------------------------------------------------------

func TestValidate_MaterialCheckIntervalTooShort(t *testing.T) {
	cfg := validConfig()
	cfg.Chains.EVM.MaterialCheck.Enabled = true
	cfg.Chains.EVM.MaterialCheck.Interval = 30 * time.Second // < 1m
	err := validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "interval must be >= 1m")
}

func TestValidate_MaterialCheckIntervalValid(t *testing.T) {
	cfg := validConfig()
	cfg.Chains.EVM.MaterialCheck.Enabled = true
	cfg.Chains.EVM.MaterialCheck.Interval = 5 * time.Minute
	err := validate(cfg)
	assert.NoError(t, err)
}

func TestValidate_MaterialCheckDisabled(t *testing.T) {
	cfg := validConfig()
	cfg.Chains.EVM.MaterialCheck.Enabled = false
	cfg.Chains.EVM.MaterialCheck.Interval = 30 * time.Second // short but disabled, so no error
	err := validate(cfg)
	assert.NoError(t, err)
}
