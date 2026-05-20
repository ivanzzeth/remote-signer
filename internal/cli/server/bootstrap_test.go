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
	// Pins the post-cleanup contract: bootstrap writes the encrypted
	// keystore to the CANONICAL path keystorePath (admin.keystore.json),
	// the public PEM to pubPath, and the DB row — no pointer files, no
	// hash-derived filenames. Daemon never needs the private key at
	// runtime; the public-key column on api_keys is the source of truth
	// for signature verification.
	t.Setenv("REMOTE_SIGNER_KEYSTORE_PASSWORD", "test-password-12345")

	tmp := t.TempDir()
	keystoreDir := tmp
	keystorePath := filepath.Join(tmp, "admin.keystore.json")
	pubPath := filepath.Join(tmp, "admin.key.pub")
	repo := newTestRepo(t)

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, keystoreDir, keystorePath, pubPath, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	// Keystore landed at the canonical path.
	if !keystore.IsEnhancedKeyFile(keystorePath) {
		t.Errorf("file at %s is not a valid enhanced keystore", keystorePath)
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
	keystorePath := filepath.Join(tmp, "admin.keystore.json")
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

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, tmp, keystorePath, pubPath, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	// No files should be created when the table already has rows.
	if _, err := os.Stat(keystorePath); !os.IsNotExist(err) {
		t.Errorf("keystore should not exist after no-op bootstrap: %v", err)
	}
}

func TestBootstrapAdminKeystoreRecoverableEnd2End(t *testing.T) {
	// Spot-check that the public PEM and the keystore's encoded
	// identifier (hex pubkey) refer to the same key — guards against a
	// mis-wire between the two writers. Also exercises
	// IsEnhancedKeyFile against the stable path so a future format
	// change has a single asserted regression site.
	t.Setenv("REMOTE_SIGNER_KEYSTORE_PASSWORD", "test-password-12345")

	tmp := t.TempDir()
	keystoreDir := tmp
	keystorePath := filepath.Join(tmp, "admin.keystore.json")
	pubPath := filepath.Join(tmp, "admin.key.pub")
	repo := newTestRepo(t)

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, keystoreDir, keystorePath, pubPath, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	pubPEMBytes, _ := os.ReadFile(pubPath)
	pubBlock, _ := pem.Decode(pubPEMBytes)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("pub PEM block invalid: %v", pubBlock)
	}
	pubParsed, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("pub key not parseable: %v", err)
	}
	pubEd, ok := pubParsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("pub is not Ed25519: %T", pubParsed)
	}
	pubFromPEMHex := hex.EncodeToString(pubEd)
	info, err := keystore.GetEnhancedKeyInfo(keystorePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Identifier != pubFromPEMHex {
		t.Errorf("keystore identifier = %q, pub PEM = %q", info.Identifier, pubFromPEMHex)
	}
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
