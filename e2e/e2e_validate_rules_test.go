//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateRules_AllRulesAndTemplates runs validate-rules on every YAML under
// rules/ and rules/templates/ so that e2e covers all rule and template files
// (see docs/SECURITY_AUDIT_REPORT.md §3).
func TestValidateRules_AllRulesAndTemplates(t *testing.T) {
	projectRoot := findProjectRoot(t)
	rulesDir := filepath.Join(projectRoot, "rules")
	templatesDir := filepath.Join(projectRoot, "rules", "templates")

	var files []string
	for _, dir := range []string{rulesDir, templatesDir} {
		entries, err := os.ReadDir(dir)
		require.NoError(t, err, "read dir %s", dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if filepath.Ext(e.Name()) != ".yaml" {
				continue
			}
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	require.NotEmpty(t, files, "no rule/template YAML files found under rules/ and rules/templates/")

	cmd := exec.Command("go", append([]string{"run", "./cmd/validate-rules/"}, files...)...)
	cmd.Dir = projectRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err, "validate-rules must pass for all rules/*.yaml and rules/templates/*.yaml (exit code 0)")
}

// TestValidateRules_MultiChainInstanceConfig verifies that validate-rules passes
// for a config with multiple instances of the same template bundle across chains
// (the matrix preset scenario: same ERC20 Template, 6 different chain_ids).
func TestValidateRules_MultiChainInstanceConfig(t *testing.T) {
	projectRoot := findProjectRoot(t)

	// Use the real config.yaml which has USDC preset rules for 6 chains
	configPath := filepath.Join(projectRoot, "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("config.yaml not found (USDC preset not deployed)")
	}

	// Check if config has multi-chain instance rules
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	configStr := string(data)
	// Must have at least 2 different chain_ids in instance rules
	hasMultiChain := false
	for _, cid := range []string{"chain_id: \"137\"", "chain_id: \"42161\"", "chain_id: \"10\""} {
		if strings.Contains(configStr, cid) {
			hasMultiChain = true
			break
		}
	}
	if !hasMultiChain {
		t.Skip("config.yaml does not have multi-chain instance rules")
	}

	cmd := exec.Command("go", "run", "./cmd/validate-rules/", "-config", configPath)
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "validate-rules must pass for multi-chain instance config.\nOutput:\n%s", string(out))

	// Verify output shows multiple rules passed
	assert.Contains(t, string(out), "passed")
	assert.Contains(t, string(out), "All rules validated successfully")
}

func findProjectRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	for dir := wd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "cmd", "validate-rules")); err == nil {
				return dir
			}
		}
	}
	require.Fail(t, "project root (with go.mod and cmd/validate-rules) not found")
	return ""
}
