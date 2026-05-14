//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAPIKeyKeygen_WritesFiles exercises `remote-signer api-key keygen --out
// path` without any daemon. We assert the file modes (0600/0644), valid PEM
// shapes, that the printed hex matches the public-key file, and the
// stdout-only mode (--print-public) returns a 64-char hex pubkey with no
// side effects on disk.
func TestAPIKeyKeygen_WritesFiles(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "alice")

	stdout, stderr, err := cli(t, "api-key", "keygen", "--out", out)
	if err != nil {
		t.Fatalf("api-key keygen: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// File presence and modes
	privPath := out + ".priv"
	pubPath := out + ".pub"
	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	if perm := privInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("priv perm = %o, want 0600", perm)
	}
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	if perm := pubInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("pub perm = %o, want 0644", perm)
	}

	// Decode private key as Ed25519 PKCS#8
	privPEM, _ := os.ReadFile(privPath)
	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil || privBlock.Type != "PRIVATE KEY" {
		t.Fatalf("priv PEM type: %v", privBlock)
	}
	rawPriv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse priv: %v", err)
	}
	edPriv, ok := rawPriv.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("priv is not Ed25519: %T", rawPriv)
	}

	// Decode public key and confirm it matches the private key's public half.
	pubPEM, _ := os.ReadFile(pubPath)
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("pub PEM type: %v", pubBlock)
	}
	rawPub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	edPub, ok := rawPub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("pub is not Ed25519: %T", rawPub)
	}
	derivedPub := edPriv.Public().(ed25519.PublicKey)
	if !derivedPub.Equal(edPub) {
		t.Errorf("priv/pub pair mismatch")
	}

	// stdout must include the same hex public key as a copy-paste hint.
	expectedHex := hex.EncodeToString(derivedPub)
	if !strings.Contains(stdout, expectedHex) {
		t.Errorf("stdout missing public-key hex %s\n%s", expectedHex, stdout)
	}
}

// TestAPIKeyKeygen_PrintPublicOnly verifies that --print-public emits only
// the 64-char hex public key on stdout and writes no files.
func TestAPIKeyKeygen_PrintPublicOnly(t *testing.T) {
	tmp := t.TempDir()
	noFiles := filepath.Join(tmp, "should-not-be-created")

	stdout, stderr, err := cli(t, "api-key", "keygen", "--out", noFiles, "--print-public")
	if err != nil {
		t.Fatalf("keygen --print-public: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	got := strings.TrimSpace(stdout)
	if len(got) != 64 {
		t.Errorf("expected 64 hex chars, got %d: %q", len(got), got)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("not hex: %v (%q)", err, got)
	}

	if _, err := os.Stat(noFiles + ".priv"); !os.IsNotExist(err) {
		t.Errorf("--print-public should not write .priv: %v", err)
	}
	if _, err := os.Stat(noFiles + ".pub"); !os.IsNotExist(err) {
		t.Errorf("--print-public should not write .pub: %v", err)
	}
}

// TestAPIKey_CreateListDelete drives the admin lifecycle through the CLI:
// flip the api-key lockdown off → restart → keygen → api-key create →
// api-key list (find the row) → api-key delete → api-key list (gone).
//
// The restart exercises the settings persistence path: a security write
// must survive a daemon restart and be observed at boot. Per-request hot
// reload of the readonly flag is intentionally deferred (see PR7b), so the
// test makes that explicit by restarting between the policy change and the
// admin call.
func TestAPIKey_CreateListDelete(t *testing.T) {
	d := startDaemon(t)

	// Flip the lockdown off and confirm the row was persisted before we
	// restart. The handler at this point still sees the boot-time value;
	// the restart below is what makes the new value effective.
	if _, _, err := d.runCLI(t, "settings", "set", "security",
		"api_keys_api_readonly=false",
	); err != nil {
		t.Fatalf("unlock api-keys management: %v", err)
	}
	home, configPath, port := d.home, d.configPath, d.port
	d.stop()

	d2 := restartInHome(t, home, configPath, port)

	// Generate a keypair for "alice".
	keyOut := filepath.Join(t.TempDir(), "alice")
	stdout, stderr, err := cli(t, "api-key", "keygen", "--out", keyOut, "--print-public")
	if err != nil {
		t.Fatalf("keygen: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	alicePubHex := strings.TrimSpace(stdout)

	// Create.
	cStdout, cStderr, cErr := d2.runCLI(t,
		"api-key", "create",
		"--id", "alice",
		"--name", "Alice Test",
		"--role", "dev",
		"--public-key", alicePubHex,
	)
	if cErr != nil {
		t.Fatalf("api-key create: %v\nstdout: %s\nstderr: %s", cErr, cStdout, cStderr)
	}

	// List and find the row.
	lStdout, lStderr, lErr := d2.runCLI(t, "api-key", "list")
	if lErr != nil {
		t.Fatalf("api-key list: %v\nstderr: %s", lErr, lStderr)
	}
	if !strings.Contains(lStdout, "alice") {
		t.Errorf("alice not in list output: %s", lStdout)
	}

	// Delete.
	dStdout, dStderr, dErr := d2.runCLI(t, "api-key", "delete", "alice")
	if dErr != nil {
		t.Fatalf("api-key delete: %v\nstdout: %s\nstderr: %s", dErr, dStdout, dStderr)
	}

	// List again and confirm it's gone.
	l2Stdout, _, l2Err := d2.runCLI(t, "api-key", "list")
	if l2Err != nil {
		t.Fatalf("api-key list (after delete): %v", l2Err)
	}
	if strings.Contains(l2Stdout, "Alice Test") {
		t.Errorf("alice still present after delete: %s", l2Stdout)
	}
}
