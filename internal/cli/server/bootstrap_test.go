package server

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	// modernc.org/sqlite registers the pure-Go "sqlite" database/sql driver.
	_ "modernc.org/sqlite"

	"github.com/ivanzzeth/ethsig/keystore"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func newTestRepo(t *testing.T) storage.APIKeyRepository {
	t.Helper()
	db, err := gorm.Open(sqlite.New(sqlite.Config{DSN: ":memory:", DriverName: "sqlite"}), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&types.APIKey{}); err != nil {
		t.Fatal(err)
	}
	repo, err := storage.NewGormAPIKeyRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBootstrapCreatesAdminWhenEmpty(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_KEYSTORE_PASSWORD", "test-password-12345")

	tmp := t.TempDir()
	keystoreDir := tmp
	ptrPath := filepath.Join(tmp, "admin.key.keystore")
	pubPath := filepath.Join(tmp, "admin.key.pub")
	repo := newTestRepo(t)

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, keystoreDir, ptrPath, pubPath, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	// Verify pointer file exists and contains a keystore path.
	ptrData, err := os.ReadFile(ptrPath)
	if err != nil {
		t.Fatal(err)
	}
	keystorePath := strings.TrimSpace(string(ptrData))
	if keystorePath == "" {
		t.Fatal("keystore pointer file is empty")
	}

	// Verify the keystore file exists and is a valid enhanced key file.
	if !keystore.IsEnhancedKeyFile(keystorePath) {
		t.Errorf("file at pointer path %s is not a valid enhanced keystore", keystorePath)
	}

	// Verify public key PEM was written.
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("pub PEM block invalid: %v", pubBlock)
	}
	if _, err := x509.ParsePKIXPublicKey(pubBlock.Bytes); err != nil {
		t.Errorf("pub key not parseable: %v", err)
	}

	// Verify the DB row was created.
	row, err := repo.Get(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if row.Source != types.APIKeySourceBootstrap {
		t.Errorf("source = %q, want %q", row.Source, types.APIKeySourceBootstrap)
	}
	if row.Role != types.RoleAdmin {
		t.Errorf("role = %q, want %q", row.Role, types.RoleAdmin)
	}
	if row.PublicKeyHex == "" {
		t.Errorf("public key hex should not be empty")
	}

	// Verify the hex public key in the DB matches the keystore identifier.
	info, err := keystore.GetEnhancedKeyInfo(keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Identifier != row.PublicKeyHex {
		t.Errorf("keystore identifier = %q, DB public_key_hex = %q", info.Identifier, row.PublicKeyHex)
	}
}

func TestBootstrapNoopWhenKeysExist(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_KEYSTORE_PASSWORD", "test-password-12345")

	tmp := t.TempDir()
	ptrPath := filepath.Join(tmp, "admin.key.keystore")
	pubPath := filepath.Join(tmp, "admin.key.pub")
	repo := newTestRepo(t)

	if err := repo.Create(context.Background(), &types.APIKey{
		ID:           "preexisting",
		Name:         "leftover",
		PublicKeyHex: "00",
		Role:         types.RoleStrategy,
		Enabled:      true,
		Source:       types.APIKeySourceAPI,
	}); err != nil {
		t.Fatal(err)
	}

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, tmp, ptrPath, pubPath, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	// No files should be created when the table already has rows.
	if _, err := os.Stat(ptrPath); !os.IsNotExist(err) {
		t.Errorf("keystore pointer file should not exist after no-op bootstrap: %v", err)
	}
}

// unlockAdminKeystoreHelper runs the unlock flow with a test password and
// validates the PEM file is written. Returns the privPath for further
// assertions, and a cleanup function.
func unlockAdminKeystoreHelper(t *testing.T, ptrPath, privPath string) func() {
	t.Helper()
	t.Setenv("REMOTE_SIGNER_ADMIN_PASSWORD", "test-password-12345")
	cleanup, err := unlockAdminKeystoreIfNeeded(ptrPath, privPath, discardLogger())
	if err != nil {
		t.Fatalf("unlockAdminKeystoreIfNeeded: %v", err)
	}
	// Verify PEM was written.
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		t.Errorf("PEM file should exist after unlock: %s", privPath)
	}
	return cleanup
}

func TestBootstrapAndUnlockRoundtrip(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_KEYSTORE_PASSWORD", "test-password-12345")

	tmp := t.TempDir()
	keystoreDir := tmp
	ptrPath := filepath.Join(tmp, "admin.key.keystore")
	pubPath := filepath.Join(tmp, "admin.key.pub")
	privPath := filepath.Join(tmp, "admin.key.priv")
	repo := newTestRepo(t)

	// Bootstrap the admin key.
	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, keystoreDir, ptrPath, pubPath, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	// Read pointer and keystore info before unlock.
	ptrData, _ := os.ReadFile(ptrPath)
	keystorePath := strings.TrimSpace(string(ptrData))

	// Unlock the keystore.
	cleanup := unlockAdminKeystoreHelper(t, ptrPath, privPath)

	// Verify the PEM is a valid Ed25519 private key.
	privPEM, _ := os.ReadFile(privPath)
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("priv PEM block invalid: %v", block)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("priv key not parseable: %v", err)
	}
	edPriv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("parsed key is not Ed25519: %T", parsed)
	}

	// Verify the public key from the PEM matches the keystore identifier.
	info, err := keystore.GetEnhancedKeyInfo(keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	expectedPub := ed25519.PrivateKey(edPriv).Public().(ed25519.PublicKey)
	expectedPubHex := hex.EncodeToString(expectedPub)
	if info.Identifier != expectedPubHex {
		t.Errorf("keystore identifier = %q, PEM public key = %q", info.Identifier, expectedPubHex)
	}

	// Run cleanup and verify priv file is removed.
	cleanup()
	if _, err := os.Stat(privPath); !os.IsNotExist(err) {
		t.Errorf("PEM should be removed after cleanup: %v", err)
	}

	// Keystore pointer and keystore file should still exist after cleanup.
	if _, err := os.Stat(ptrPath); os.IsNotExist(err) {
		t.Errorf("keystore pointer should survive cleanup")
	}
	if _, err := os.Stat(keystorePath); os.IsNotExist(err) {
		t.Errorf("keystore file should survive cleanup")
	}
}

func TestUnlockNoopWhenNoPointer(t *testing.T) {
	tmp := t.TempDir()
	privPath := filepath.Join(tmp, "admin.key.priv")

	cleanup, err := unlockAdminKeystoreIfNeeded(
		filepath.Join(tmp, "nonexistent.keystore"),
		privPath,
		discardLogger(),
	)
	if err != nil {
		t.Fatalf("unlockAdminKeystoreIfNeeded with no pointer should not error: %v", err)
	}
	cleanup()
	if _, err := os.Stat(privPath); !os.IsNotExist(err) {
		t.Errorf("PEM should not exist when no keystore pointer: %v", err)
	}
}

func TestUnlockNoopWhenPEMAlreadyExists(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_ADMIN_PASSWORD", "test-password-12345")

	tmp := t.TempDir()
	keystoreDir := tmp
	ptrPath := filepath.Join(tmp, "admin.key.keystore")
	pubPath := filepath.Join(tmp, "admin.key.pub")
	privPath := filepath.Join(tmp, "admin.key.priv")
	repo := newTestRepo(t)

	// Bootstrap and unlock first.
	t.Setenv("REMOTE_SIGNER_KEYSTORE_PASSWORD", "test-password-12345")
	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, keystoreDir, ptrPath, pubPath, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}
	cleanup1 := unlockAdminKeystoreHelper(t, ptrPath, privPath)
	cleanup1()

	// Second unlock should still work because the PEM was cleaned up.
	cleanup2 := unlockAdminKeystoreHelper(t, ptrPath, privPath)
	cleanup2()

	// Write the PEM manually and call unlock again — it should be a no-op.
	if err := os.WriteFile(privPath, []byte("fake-key"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanup3, err := unlockAdminKeystoreIfNeeded(ptrPath, privPath, discardLogger())
	if err != nil {
		t.Fatalf("unlock with existing PEM should not error: %v", err)
	}
	// Verify it did NOT overwrite our file.
	data, _ := os.ReadFile(privPath)
	if string(data) != "fake-key" {
		t.Errorf("unlock should not overwrite existing PEM")
	}
	cleanup3()
}

func TestBootstrapAgentKeyCreatesWhenNoAgentKey(t *testing.T) {
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "agent.key.priv")
	pub := filepath.Join(tmp, "agent.key.pub")
	repo := newTestRepo(t)

	if err := bootstrapAgentKeyIfNeeded(context.Background(), repo, priv, pub, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	privInfo, err := os.Stat(priv)
	if err != nil {
		t.Fatal(err)
	}
	if privInfo.Mode().Perm() != 0600 {
		t.Errorf("priv mode = %o, want 0600", privInfo.Mode().Perm())
	}
	pubInfo, err := os.Stat(pub)
	if err != nil {
		t.Fatal(err)
	}
	if pubInfo.Mode().Perm() != 0644 {
		t.Errorf("pub mode = %o, want 0644", pubInfo.Mode().Perm())
	}

	privPEM, _ := os.ReadFile(priv)
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("priv PEM block invalid: %v", block)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("priv key not parseable: %v", err)
	}

	pubPEM, _ := os.ReadFile(pub)
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("pub PEM block invalid: %v", pubBlock)
	}
	if _, err := x509.ParsePKIXPublicKey(pubBlock.Bytes); err != nil {
		t.Errorf("pub key not parseable: %v", err)
	}

	row, err := repo.Get(context.Background(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	if row.Source != types.APIKeySourceBootstrap {
		t.Errorf("source = %q, want %q", row.Source, types.APIKeySourceBootstrap)
	}
	if row.Role != types.RoleAgent {
		t.Errorf("role = %q, want %q", row.Role, types.RoleAgent)
	}
	if row.ID != "agent" {
		t.Errorf("id = %q, want %q", row.ID, "agent")
	}
}

func TestBootstrapAgentKeyNoopWhenAgentKeyExists(t *testing.T) {
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "agent.key.priv")
	pub := filepath.Join(tmp, "agent.key.pub")
	repo := newTestRepo(t)

	if err := repo.Create(context.Background(), &types.APIKey{
		ID:           "agent",
		Name:         "agent (bootstrap)",
		PublicKeyHex: "00",
		Role:         types.RoleAgent,
		Enabled:      true,
		Source:       types.APIKeySourceBootstrap,
	}); err != nil {
		t.Fatal(err)
	}

	if err := bootstrapAgentKeyIfNeeded(context.Background(), repo, priv, pub, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(priv); !os.IsNotExist(err) {
		t.Errorf("priv file should not exist after no-op bootstrap: %v", err)
	}
}

// TestBootstrapAgentKeyNoopWhenNonBootstrapKeyExists verifies that
// bootstrapAgentKeyIfNeeded is a no-op when an agent key already exists with a
// non-bootstrap source (e.g. config sync residue, partial bootstrap from a
// previous run). This guards against the UNIQUE constraint crash in WEB-65.
func TestBootstrapAgentKeyNoopWhenNonBootstrapKeyExists(t *testing.T) {
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "agent.key.priv")
	pub := filepath.Join(tmp, "agent.key.pub")
	repo := newTestRepo(t)

	// Simulate a leftover agent key created by a non-bootstrap source
	// (e.g. config sync, partial bootstrap that wrote the row but not the files).
	if err := repo.Create(context.Background(), &types.APIKey{
		ID:           "agent",
		Name:         "agent (config sync)",
		PublicKeyHex: "00",
		Role:         types.RoleAgent,
		Enabled:      true,
		Source:       types.APIKeySourceAPI,
	}); err != nil {
		t.Fatal(err)
	}

	if err := bootstrapAgentKeyIfNeeded(context.Background(), repo, priv, pub, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(priv); !os.IsNotExist(err) {
		t.Errorf("priv file should not exist after no-op bootstrap: %v", err)
	}
}

func TestBootstrapAgentKeyCreatesWhenAdminKeyExists(t *testing.T) {
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "agent.key.priv")
	pub := filepath.Join(tmp, "agent.key.pub")
	repo := newTestRepo(t)

	// First create an admin key — this should NOT block agent key creation
	if err := repo.Create(context.Background(), &types.APIKey{
		ID:           "admin",
		Name:         "admin (bootstrap)",
		PublicKeyHex: "00",
		Role:         types.RoleAdmin,
		Enabled:      true,
		Source:       types.APIKeySourceBootstrap,
	}); err != nil {
		t.Fatal(err)
	}

	if err := bootstrapAgentKeyIfNeeded(context.Background(), repo, priv, pub, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	row, err := repo.Get(context.Background(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	if row.Source != types.APIKeySourceBootstrap {
		t.Errorf("source = %q, want %q", row.Source, types.APIKeySourceBootstrap)
	}
	if row.Role != types.RoleAgent {
		t.Errorf("role = %q, want %q", row.Role, types.RoleAgent)
	}
}
