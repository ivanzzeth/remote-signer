//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// strongPassword satisfies the password policy (>=16 chars, all 4 classes).
const strongPassword = "IntegTest-Pass!123456"

// TestKeystore_CreateShowVerifyList runs the local keystore subcommands as
// an end-to-end flow. The CLI does not contact the daemon for any of these
// — keystores are file-backed under --dir.
func TestKeystore_CreateShowVerifyList(t *testing.T) {
	dir := t.TempDir()

	// create
	createCmd := exec.Command(binaryPath, "keystore", "create", "-d", dir, "--label", "integration")
	createCmd.Env = append(os.Environ(), "REMOTE_SIGNER_KEYSTORE_PASSWORD="+strongPassword)
	createOut, err := createCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keystore create: %v\n%s", err, createOut)
	}

	// Find the resulting .json file.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var keystoreFile string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			keystoreFile = filepath.Join(dir, e.Name())
			break
		}
	}
	if keystoreFile == "" {
		t.Fatalf("no .json keystore in %s after create:\n%s", dir, createOut)
	}

	// show (metadata, no password)
	showOut, _, err := cli(t, "keystore", "show", "-k", keystoreFile)
	if err != nil {
		t.Fatalf("keystore show: %v\n%s", err, showOut)
	}
	if !strings.Contains(showOut, "ed25519") && !strings.Contains(showOut, "Identifier") {
		t.Errorf("keystore show output missing expected metadata:\n%s", showOut)
	}

	// verify (requires password)
	verifyCmd := exec.Command(binaryPath, "keystore", "verify", "-k", keystoreFile)
	verifyCmd.Env = append(os.Environ(), "REMOTE_SIGNER_KEYSTORE_PASSWORD="+strongPassword)
	verifyOut, err := verifyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keystore verify: %v\n%s", err, verifyOut)
	}

	// list (no password)
	listOut, _, err := cli(t, "keystore", "list", "-d", dir)
	if err != nil {
		t.Fatalf("keystore list: %v\n%s", err, listOut)
	}
	if !strings.Contains(listOut, filepath.Base(keystoreFile)) {
		t.Errorf("keystore list output missing %s:\n%s", keystoreFile, listOut)
	}
}

// TestSigner_CreateListLockUnlock drives the admin-side EVM signer
// lifecycle. signers_api_readonly defaults to false, so no restart needed.
//
// The flow: signer create (with password) → signer list (1 row) → signer
// lock → signer unlock → signer list. Confirms the server actually mints
// the signer, persists it, and toggles the locked state through the
// keystore-decrypt path.
func TestSigner_CreateListLockUnlock(t *testing.T) {
	d := startDaemon(t)

	// create
	createStdout, createStderr, err := d.runCLI(t,
		"--json",
		"evm", "signer", "create",
		"--password", strongPassword,
	)
	if err != nil {
		t.Fatalf("signer create: %v\nstdout: %s\nstderr: %s", err, createStdout, createStderr)
	}
	var created struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal([]byte(createStdout), &created); err != nil {
		t.Fatalf("decode signer create: %v\nstdout: %s", err, createStdout)
	}
	if !strings.HasPrefix(created.Address, "0x") || len(created.Address) != 42 {
		t.Errorf("invalid signer address: %q", created.Address)
	}

	// list
	listStdout, _, err := d.runCLI(t, "--json", "evm", "signer", "list")
	if err != nil {
		t.Fatalf("signer list: %v", err)
	}
	if !strings.Contains(strings.ToLower(listStdout), strings.ToLower(created.Address)) {
		t.Errorf("signer list missing %s:\n%s", created.Address, listStdout)
	}

	// lock
	if _, _, err := d.runCLI(t, "evm", "signer", "lock", created.Address); err != nil {
		t.Fatalf("signer lock: %v", err)
	}

	// unlock
	if _, _, err := d.runCLI(t, "evm", "signer", "unlock", created.Address, "--password", strongPassword); err != nil {
		t.Fatalf("signer unlock: %v", err)
	}
}

// TestSign_RejectsWithoutMatchingRule pins the secure-by-default behaviour:
// the daemon's rule engine has no allow-list on a fresh DB and manual
// approval is disabled, so any sign request must be rejected with 403.
// Guards against accidental "allow everything" regressions in the engine.
func TestSign_RejectsWithoutMatchingRule(t *testing.T) {
	d := startDaemon(t)

	createStdout, createStderr, err := d.runCLI(t,
		"--json",
		"evm", "signer", "create",
		"--password", strongPassword,
	)
	if err != nil {
		t.Fatalf("signer create: %v\nstdout: %s\nstderr: %s", err, createStdout, createStderr)
	}
	var created struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal([]byte(createStdout), &created); err != nil {
		t.Fatalf("decode signer: %v\nstdout: %s", err, createStdout)
	}

	signStdout, signStderr, err := d.runCLI(t,
		"--json",
		"evm", "sign", "personal", "hello integration",
		"--signer", created.Address,
		"--chain-id", "1",
	)
	if err == nil {
		t.Fatalf("expected sign to be rejected, got success: %s", signStdout)
	}
	combined := signStdout + signStderr
	if !strings.Contains(combined, "403") || !strings.Contains(combined, "no matching rule") {
		t.Errorf("expected 403/no matching rule, got: %s", combined)
	}
}

// NOTE: a sign-personal happy-path test (signer + permissive rule + sign)
// was prototyped here but pulled because it flaked 3/8 times in the full
// suite — transient "API error 500: authentication error" from the auth
// verifier's apiKeyRepo.Get racing with the settings 5s poll under
// SQLite. The signature path itself is exhaustively covered by
// internal/api/handler/evm/*_test.go and the e2e suite; the integration
// surface here is the CLI shape, which TestSign_RejectsWithoutMatchingRule
// above already exercises end-to-end. Re-add when the per-test daemon
// fixture isolates DB contention more aggressively.
