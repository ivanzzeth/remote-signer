//go:build integration

package integration

import (
	"crypto/x509"
	"encoding/pem"
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
//   - admin.key.priv exists (0600) and decodes as an Ed25519 PKCS#8 key.
//   - admin.key.pub exists (0644).
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

	privPath := d.adminKeyPath()
	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat admin.key.priv: %v", err)
	}
	if perm := privInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("admin.key.priv perm = %o, want 0600", perm)
	}
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("admin.key.priv is not a PRIVATE KEY PEM: %v", block)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("admin.key.priv parse: %v", err)
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
// stops the daemon, and boots again against the same home. The keypair
// files must be byte-identical (no rotation) and admin auth must still work
// against the existing credentials.
func TestBootstrap_SecondLaunchIsNoop(t *testing.T) {
	d := startDaemon(t)
	firstPriv, err := os.ReadFile(d.adminKeyPath())
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
	secondPriv, err := os.ReadFile(d2.adminKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(firstPriv) != string(secondPriv) {
		t.Errorf("admin.key.priv rotated on second launch")
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
