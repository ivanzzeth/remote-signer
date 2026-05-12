package server

import (
	"context"
	"crypto/x509"
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
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "admin.key.priv")
	pub := filepath.Join(tmp, "admin.key.pub")
	repo := newTestRepo(t)

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, priv, pub, discardLogger()); err != nil {
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
}

func TestBootstrapNoopWhenKeysExist(t *testing.T) {
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "admin.key.priv")
	pub := filepath.Join(tmp, "admin.key.pub")
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

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, priv, pub, discardLogger()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(priv); !os.IsNotExist(err) {
		t.Errorf("priv file should not exist after no-op bootstrap: %v", err)
	}
	if _, err := repo.Get(context.Background(), "admin"); err == nil {
		t.Errorf("admin key should not exist after no-op bootstrap")
	}
}
