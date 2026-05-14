//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTemplate_CRUD covers the admin template surface: list (empty) →
// create → get → list (1 row) → delete → list (empty). Templates are
// admin-managed only — the daemon is restarted with rules_api_readonly off
// before any mutation.
func TestTemplate_CRUD(t *testing.T) {
	d := startDaemon(t)
	d = restartWithRulesAPIOpen(t, d)

	stdout, _, err := d.runCLI(t, "--json", "template", "list")
	if err != nil {
		t.Fatalf("template list (empty): %v", err)
	}
	if !strings.Contains(stdout, "[]") {
		t.Errorf("expected empty template list, got %s", stdout)
	}

	tmplFile := filepath.Join(t.TempDir(), "tmpl.yaml")
	const tmplYAML = `name: integration-template
type: evm_address_list
mode: whitelist
enabled: true
description: integration test template
variables:
  - name: target
    type: address
    required: true
config:
  addresses:
    - "${target}"
`
	if err := os.WriteFile(tmplFile, []byte(tmplYAML), 0600); err != nil {
		t.Fatal(err)
	}

	createStdout, createStderr, err := d.runCLI(t, "template", "create", "-f", tmplFile)
	if err != nil {
		t.Fatalf("template create: %v\nstdout: %s\nstderr: %s", err, createStdout, createStderr)
	}
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(createStdout), &created); err != nil {
		t.Fatalf("decode create: %v\nstdout: %s", err, createStdout)
	}
	if created.ID == "" {
		t.Fatalf("server returned no template id: %s", createStdout)
	}
	if created.Name != "integration-template" {
		t.Errorf("template name mismatch: %+v", created)
	}

	getStdout, _, err := d.runCLI(t, "--json", "template", "get", created.ID)
	if err != nil {
		t.Fatalf("template get: %v", err)
	}
	if !strings.Contains(getStdout, created.ID) {
		t.Errorf("template get missing id %s: %s", created.ID, getStdout)
	}

	listStdout, _, err := d.runCLI(t, "--json", "template", "list")
	if err != nil {
		t.Fatalf("template list: %v", err)
	}
	if !strings.Contains(listStdout, created.ID) {
		t.Errorf("template list missing id %s: %s", created.ID, listStdout)
	}

	if _, _, err := d.runCLI(t, "template", "delete", created.ID); err != nil {
		t.Fatalf("template delete: %v", err)
	}
	listAfter, _, err := d.runCLI(t, "--json", "template", "list")
	if err != nil {
		t.Fatalf("template list after delete: %v", err)
	}
	if strings.Contains(listAfter, created.ID) {
		t.Errorf("template still present after delete: %s", listAfter)
	}
}
