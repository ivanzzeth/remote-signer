//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestBootstrap_SoftStart_ViaHTTP exercises the new deferred-bootstrap
// flow: daemon comes up without REMOTE_SIGNER_KEYSTORE_PASSWORD, no admin
// row exists, and the unauthenticated POST /api/v1/bootstrap/admin
// finishes setup. Mirrors the docker/launchd/systemd scenario where the
// operator can't or won't ship a keystore password in the daemon's env.
func TestBootstrap_SoftStart_ViaHTTP(t *testing.T) {
	d := startDaemon(t, withoutKeystorePassword())

	// /health must still respond even though admin doesn't exist yet —
	// the daemon's HTTP server has to be reachable so the bootstrap
	// endpoint can be hit.
	if resp, err := http.Get(d.url() + "/health"); err != nil {
		t.Fatalf("health probe failed: %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/health = %d on soft-start, want 200", resp.StatusCode)
		}
	}

	// Pre-bootstrap status should report needs_bootstrap=true.
	if needs := getBootstrapStatus(t, d.url()); !needs {
		t.Fatalf("pre-bootstrap status reports needs_bootstrap=false; want true")
	}

	// On disk we should see no admin keystore yet — soft-start means
	// nothing was written, just listening.
	if _, err := os.Stat(d.adminKeystorePath()); !os.IsNotExist(err) {
		t.Fatalf("admin.keystore.json exists before bootstrap completes: %v", err)
	}

	// Complete the bootstrap via HTTP. The 200 carries back the paths
	// the daemon wrote — assert they match what helpers_test expects.
	resp := postBootstrapAdmin(t, d.url(), "integration-test")
	if resp.Status != "ok" {
		t.Fatalf("bootstrap status = %q, want ok (body=%+v)", resp.Status, resp)
	}
	if resp.KeystorePath != d.adminKeystorePath() {
		t.Errorf("keystore_path = %q, want %q", resp.KeystorePath, d.adminKeystorePath())
	}
	if len(resp.PubKeyHex) != 64 {
		t.Errorf("public_key_hex length = %d, want 64", len(resp.PubKeyHex))
	}

	// Files should exist with the same permissions the startup path
	// would have produced.
	info, err := os.Stat(d.adminKeystorePath())
	if err != nil {
		t.Fatalf("stat admin.keystore.json post-bootstrap: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("admin.keystore.json perm = %o, want 0600", perm)
	}

	// Status should flip after success — second visitor must not see
	// the bootstrap form.
	if needs := getBootstrapStatus(t, d.url()); needs {
		t.Errorf("post-bootstrap status reports needs_bootstrap=true; want false")
	}

	// A second POST must be rejected with 410 Gone (the window has
	// closed) so a racing caller can't blow away the just-created admin.
	code, _ := postBootstrapAdminRaw(t, d.url(), "another-password")
	if code != http.StatusGone {
		t.Errorf("second bootstrap POST = %d, want 410", code)
	}

	// The freshly-bootstrapped admin must now authenticate. /metrics
	// is admin-only; a successful Prometheus body confirms the public
	// key the handler wrote is the one the auth layer reads.
	stdout, stderr, err := d.runCLI(t, "metrics")
	if err != nil {
		t.Fatalf("metrics call failed after HTTP bootstrap: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "# HELP") {
		t.Errorf("/metrics body should be Prometheus exposition: %s", stdout)
	}
}

// TestBootstrap_SoftStart_StatusFalseAfterEnvBootstrap pins the polarity
// from the other direction: when env-var bootstrap ran at startup, the
// status endpoint immediately reports needs_bootstrap=false. The SPA
// uses this to route directly to the login page; a wrong polarity here
// would loop new operators back into the setup form on every visit.
func TestBootstrap_SoftStart_StatusFalseAfterEnvBootstrap(t *testing.T) {
	d := startDaemon(t) // default: env var set, admin bootstrapped inline
	if needs := getBootstrapStatus(t, d.url()); needs {
		t.Errorf("status reports needs_bootstrap=true after env-var bootstrap; want false")
	}
}

type bootstrapAdminResponse struct {
	Status       string `json:"status"`
	KeystorePath string `json:"keystore_path"`
	PubKeyPath   string `json:"pub_key_path"`
	PubKeyHex    string `json:"public_key_hex"`
}

func getBootstrapStatus(t *testing.T, baseURL string) bool {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(baseURL + "/api/v1/bootstrap/status")
	if err != nil {
		t.Fatalf("GET /api/v1/bootstrap/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status endpoint HTTP %d: %s", resp.StatusCode, string(body))
	}
	var s struct {
		NeedsBootstrap bool `json:"needs_bootstrap"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return s.NeedsBootstrap
}

func postBootstrapAdmin(t *testing.T, baseURL, password string) bootstrapAdminResponse {
	t.Helper()
	code, body := postBootstrapAdminRaw(t, baseURL, password)
	if code != http.StatusOK {
		t.Fatalf("bootstrap admin POST = %d: %s", code, body)
	}
	var resp bootstrapAdminResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode bootstrap admin response: %v (body=%s)", err, body)
	}
	return resp
}

func postBootstrapAdminRaw(t *testing.T, baseURL, password string) (int, string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"password": password})
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/bootstrap/admin", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST bootstrap admin: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}
