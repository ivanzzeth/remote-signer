//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBootstrap_FirstLaunch boots the daemon against a brand-new home
// directory and asserts the full zero-config story:
//
//   - The home dir is created with 0700.
//   - admin.keystore.json exists (0600) and parses as a v3 enhanced
//     keystore wrapping the bootstrap Ed25519 private key.
//   - admin.key.pub exists (0644) — the unencrypted public half is still
//     written alongside so JWT verification and `doctor` can read it
//     without unlocking the keystore.
//   - remote-signer.db exists (DB was migrated).
//   - /health returns 200 with status=ok.
func TestBootstrap_FirstLaunch(t *testing.T) {
	d := startDaemon(t)

	info, err := os.Stat(d.home)
	if err != nil {
		t.Fatalf("stat home: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("home perm = %o, want 0700", perm)
	}

	ksPath := d.adminKeystorePath()
	ksInfo, err := os.Stat(ksPath)
	if err != nil {
		t.Fatalf("stat admin.keystore.json: %v", err)
	}
	if perm := ksInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("admin.keystore.json perm = %o, want 0600", perm)
	}
	// Validate keystore shape — the Ed25519-encrypted format written by
	// keystore.CreateEnhancedKey carries {version, key_type, identifier,
	// crypto, label}. We don't decrypt here (that needs the password +
	// scrypt round-trip, covered by the keystore unit tests); we just
	// confirm bootstrap wrote a syntactically valid keystore and not a
	// stray placeholder.
	ksRaw, err := os.ReadFile(ksPath)
	if err != nil {
		t.Fatal(err)
	}
	var ks struct {
		Version    int             `json:"version"`
		KeyType    string          `json:"key_type"`
		Identifier string          `json:"identifier"`
		Crypto     json.RawMessage `json:"crypto"`
		Label      string          `json:"label"`
	}
	if err := json.Unmarshal(ksRaw, &ks); err != nil {
		t.Fatalf("admin.keystore.json is not valid JSON: %v", err)
	}
	if ks.Version == 0 || ks.KeyType == "" || ks.Identifier == "" || len(ks.Crypto) == 0 {
		t.Errorf("admin.keystore.json missing required fields: %+v", ks)
	}
	if ks.KeyType != "ed25519" {
		t.Errorf("admin.keystore.json key_type = %q, want ed25519", ks.KeyType)
	}

	pubPath := filepath.Join(d.home, "apikeys", "admin.key.pub")
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat admin.key.pub: %v", err)
	}
	if perm := pubInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("admin.key.pub perm = %o, want 0644", perm)
	}

	if _, err := os.Stat(filepath.Join(d.home, "remote-signer.db")); err != nil {
		t.Errorf("remote-signer.db should exist: %v", err)
	}

	resp, err := http.Get(d.url() + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("/health body should contain status=ok: %s", body)
	}
}

// TestBootstrap_SecondLaunchIsNoop boots once, captures the admin key,
// stops the daemon, and boots again against the same home. The keystore
// + public-key files must be byte-identical (no rotation) and admin auth
// must still work against the existing credentials.
func TestBootstrap_SecondLaunchIsNoop(t *testing.T) {
	d := startDaemon(t)
	firstKS, err := os.ReadFile(d.adminKeystorePath())
	if err != nil {
		t.Fatal(err)
	}
	firstPub, err := os.ReadFile(filepath.Join(d.home, "apikeys", "admin.key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	home, configPath, port := d.home, d.configPath, d.port
	d.stop()

	d2 := restartInHome(t, home, configPath, port)
	secondKS, err := os.ReadFile(d2.adminKeystorePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(firstKS) != string(secondKS) {
		t.Errorf("admin.keystore.json rotated on second launch")
	}
	secondPub, err := os.ReadFile(filepath.Join(d2.home, "apikeys", "admin.key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if string(firstPub) != string(secondPub) {
		t.Errorf("admin.key.pub rotated on second launch")
	}

	// The original admin credential must still authenticate against the
	// service. /metrics is admin-only, so a successful response confirms
	// both that the row in api_keys was not re-created and that the
	// signature path works end-to-end.
	stdout, stderr, err := d2.runCLI(t, "metrics")
	if err != nil {
		t.Fatalf("metrics call failed after restart: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "# HELP") {
		t.Errorf("/metrics body should be Prometheus exposition: %s", stdout)
	}
}
