//go:build integration

package integration

import (
	"strings"
	"testing"
)

// TestSettings_ShowAllGroups confirms every settings group exposed by the
// admin handler returns valid JSON. This pins the group catalogue against
// accidental removal in future PRs.
func TestSettings_ShowAllGroups(t *testing.T) {
	d := startDaemon(t)

	groups := []string{
		"security",
		"notify",
		"audit_monitor",
		"evm.dynamic_blocklist",
		"evm.simulation",
		"evm.foundry",
		"evm.rpc_gateway",
		"evm.material_check",
	}
	for _, g := range groups {
		g := g
		t.Run(g, func(t *testing.T) {
			stdout, stderr, err := d.runCLI(t, "settings", "show", g)
			if err != nil {
				t.Fatalf("settings show %s: %v\nstdout: %s\nstderr: %s", g, err, stdout, stderr)
			}
			if !strings.HasPrefix(strings.TrimSpace(stdout), "{") {
				t.Errorf("settings show %s should print a JSON object, got %q", g, stdout)
			}
		})
	}
}

// TestSettings_SetSecurity_Persists writes a security field via the CLI and
// asserts the value is observed by a subsequent show. This is the basic
// admin-side write path that PR7b introduced.
func TestSettings_SetSecurity_Persists(t *testing.T) {
	d := startDaemon(t)

	if _, _, err := d.runCLI(t, "settings", "set", "security", "ip_rate_limit=999"); err != nil {
		t.Fatalf("settings set security: %v", err)
	}

	stdout, _, err := d.runCLI(t, "settings", "show", "security")
	if err != nil {
		t.Fatalf("settings show security: %v", err)
	}
	if !strings.Contains(stdout, `"ip_rate_limit": 999`) {
		t.Errorf("ip_rate_limit not 999 after set: %s", stdout)
	}
}

// TestSettings_DotPath_NestedField exercises the CLI's dotted-key support
// (introduced in PR7c) on the notify snapshot — the recipient list is two
// levels deep, so a flat key=value would silently no-op.
func TestSettings_DotPath_NestedField(t *testing.T) {
	d := startDaemon(t)

	if _, stderr, err := d.runCLI(t,
		"settings", "set", "notify",
		`channels.slack=["C12345","C67890"]`,
	); err != nil {
		t.Fatalf("settings set notify channels.slack: %v\nstderr: %s", err, stderr)
	}

	stdout, _, err := d.runCLI(t, "settings", "show", "notify")
	if err != nil {
		t.Fatalf("settings show notify: %v", err)
	}
	if !strings.Contains(stdout, `"C12345"`) || !strings.Contains(stdout, `"C67890"`) {
		t.Errorf("slack channels missing from notify snapshot: %s", stdout)
	}
}

// TestSettings_UnknownGroup_Returns400 pins the handler's rejection of an
// unknown :group so a typo at the CLI doesn't silently no-op.
func TestSettings_UnknownGroup_Returns400(t *testing.T) {
	d := startDaemon(t)

	stdout, stderr, err := d.runCLI(t, "settings", "show", "not_a_real_group")
	if err == nil {
		t.Errorf("expected non-zero exit for unknown group, got stdout=%s stderr=%s", stdout, stderr)
	}
}
