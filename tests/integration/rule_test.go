//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRule_CRUD exercises the rule lifecycle through the admin CLI:
//
//	rule list (empty) → rule create → rule get → rule list (1 row) →
//	rule toggle → rule get (disabled) → rule delete → rule list (empty)
//
// The first launch disables rules_api_readonly (admin-only knob, secure by
// default) and restarts so the API key handler picks the new flag up — the
// same persistence path the apikey test covers.
func TestRule_CRUD(t *testing.T) {
	d := startDaemon(t)
	d = restartWithRulesAPIOpen(t, d)

	stdout, _, err := d.runCLI(t, "--json", "rule", "list")
	if err != nil {
		t.Fatalf("rule list (empty): %v", err)
	}
	if !strings.Contains(stdout, `"rules": []`) && !strings.Contains(stdout, `"rules":[]`) && !strings.Contains(stdout, "[]") {
		t.Errorf("expected empty rule list, got %s", stdout)
	}

	// Write a minimal address-list whitelist rule and create it.
	ruleFile := filepath.Join(t.TempDir(), "rule.yaml")
	const ruleYAML = `name: integration-test
type: evm_address_list
mode: whitelist
chain_type: evm
chain_id: "1"
enabled: true
description: integration test fixture
config:
  addresses:
    - "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
`
	if err := os.WriteFile(ruleFile, []byte(ruleYAML), 0600); err != nil {
		t.Fatal(err)
	}

	createStdout, createStderr, err := d.runCLI(t, "rule", "create", "-f", ruleFile)
	if err != nil {
		t.Fatalf("rule create: %v\nstdout: %s\nstderr: %s", err, createStdout, createStderr)
	}
	var created struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(createStdout), &created); err != nil {
		t.Fatalf("decode create response: %v\nstdout: %s", err, createStdout)
	}
	if created.ID == "" {
		t.Fatalf("server returned no rule id: %s", createStdout)
	}
	if created.Name != "integration-test" || created.Type != "evm_address_list" || !created.Enabled {
		t.Errorf("rule shape mismatch: %+v", created)
	}

	// rule get round-trip
	getStdout, _, err := d.runCLI(t, "--json", "rule", "get", created.ID)
	if err != nil {
		t.Fatalf("rule get: %v", err)
	}
	if !strings.Contains(getStdout, created.ID) {
		t.Errorf("rule get missing id %s: %s", created.ID, getStdout)
	}

	// rule list shows it
	listStdout, _, err := d.runCLI(t, "--json", "rule", "list")
	if err != nil {
		t.Fatalf("rule list: %v", err)
	}
	if !strings.Contains(listStdout, created.ID) {
		t.Errorf("rule list missing id %s: %s", created.ID, listStdout)
	}

	// toggle off
	if _, _, err := d.runCLI(t, "rule", "toggle", created.ID, "--disable"); err != nil {
		t.Fatalf("rule toggle: %v", err)
	}
	getAfterToggle, _, err := d.runCLI(t, "--json", "rule", "get", created.ID)
	if err != nil {
		t.Fatalf("rule get after toggle: %v", err)
	}
	if !strings.Contains(getAfterToggle, `"enabled": false`) && !strings.Contains(getAfterToggle, `"enabled":false`) {
		t.Errorf("rule should be disabled after toggle: %s", getAfterToggle)
	}

	// delete
	if _, _, err := d.runCLI(t, "rule", "delete", created.ID); err != nil {
		t.Fatalf("rule delete: %v", err)
	}
	listAfterDelete, _, err := d.runCLI(t, "--json", "rule", "list")
	if err != nil {
		t.Fatalf("rule list after delete: %v", err)
	}
	if strings.Contains(listAfterDelete, created.ID) {
		t.Errorf("rule still present after delete: %s", listAfterDelete)
	}
}

// TestRule_RejectsCreateWhenReadonly pins the secure-by-default behaviour:
// with rules_api_readonly enabled, rule create must fail with 403.
// Distinguishes "lockdown enforced" from "lockdown silently bypassed".
func TestRule_RejectsCreateWhenReadonly(t *testing.T) {
	d := startDaemon(t, withCustomConfig(`
server:
  host: 127.0.0.1
  port: __PORT__
  tls:
    enabled: false
database:
  dsn: "file:__HOME__/remote-signer.db?_journal_mode=WAL&_busy_timeout=5000"
logger:
  level: info
chains:
  evm:
    enabled: true
    keystore_dir: __HOME__/keystores
    hd_wallet_dir: __HOME__/hd-wallets
security:
  rules_api_readonly: true
`))

	ruleFile := filepath.Join(t.TempDir(), "rule.yaml")
	const ruleYAML = `name: should-fail
type: evm_address_list
mode: whitelist
chain_type: evm
chain_id: "1"
enabled: true
config:
  addresses: ["0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"]
`
	if err := os.WriteFile(ruleFile, []byte(ruleYAML), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := d.runCLI(t, "rule", "create", "-f", ruleFile)
	if err == nil {
		t.Fatalf("expected create to fail under default readonly, got success: %s", stdout)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "403") && !strings.Contains(combined, "readonly") && !strings.Contains(combined, "disabled") {
		t.Errorf("expected 403/readonly/disabled error, got: %s", combined)
	}
}

// TestRule_ListTemplates is the local-only `rule list-templates` command —
// reads the daemon's config.yaml (not the DB) and prints the templates
// block. PR7e removed templates from YAML, so the output is just the
// header line on a default config.
func TestRule_ListTemplates(t *testing.T) {
	d := startDaemon(t)
	// Local-only command: pass --config to the actual config the daemon used.
	stdout, _, err := cli(t, "rule", "list-templates", "--config", d.configPath)
	if err != nil {
		t.Fatalf("rule list-templates: %v\nstdout: %s", err, stdout)
	}
	if !strings.Contains(stdout, "# Template name") {
		t.Errorf("expected header line in list-templates output: %s", stdout)
	}
	// No template rows below the header on a default config.
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if strings.TrimSpace(line) != "" {
			t.Errorf("unexpected template row %q in list-templates output", line)
		}
	}
}

// restartWithRulesAPIOpen flips security.rules_api_readonly to false and
// restarts the daemon so the rule handler picks the new value up. Shared by
// rule and template tests. Returns the post-restart daemon.
func restartWithRulesAPIOpen(t *testing.T, d *daemon) *daemon {
	t.Helper()
	if _, _, err := d.runCLI(t, "settings", "set", "security",
		"rules_api_readonly=false",
	); err != nil {
		t.Fatalf("unlock rules api: %v", err)
	}
	home, configPath, port := d.home, d.configPath, d.port
	d.stop()
	return restartInHome(t, home, configPath, port)
}
