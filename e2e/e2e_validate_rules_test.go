//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

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
	for _, dir := range []string{rulesDir} {
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
	// Walk templates recursively (templates live in subdirectories like evm/)
	filepath.WalkDir(templatesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if filepath.Ext(d.Name()) != ".yaml" {
			return nil
		}
		// Skip sign_type_allowlist: uses json-type variables that require
		// JSON-aware substitution (not handled by string-based placeholder replace).
		if d.Name() == "sign_type_allowlist.yaml" {
			return nil
		}
		files = append(files, path)
		return nil
	})
	require.NotEmpty(t, files, "no rule/template YAML files found under rules/ and rules/templates/")

	cmd := exec.Command("go", append([]string{"run", "./cmd/remote-signer", "validate"}, files...)...)
	cmd.Dir = projectRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err, "validate-rules must pass for all rules/*.yaml and rules/templates/*.yaml (exit code 0)")
}

func findProjectRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	for dir := wd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "cmd", "remote-signer")); err == nil {
				return dir
			}
		}
	}
	require.Fail(t, "project root (with go.mod and cmd/remote-signer) not found")
	return ""
}
