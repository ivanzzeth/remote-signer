package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// bootstrapAdminKeyIfNeeded checks whether any API keys exist and, if not,
// generates an Ed25519 admin keypair, writes the private key to
// <home>/admin.key.priv (0600) and the public key to <home>/admin.key.pub
// (0644), and inserts a corresponding api_keys row with source="bootstrap".
//
// The private key material is never written to logs or stderr — only the file
// paths and hex public key are surfaced, so log shippers (systemd journal,
// Docker logs) never see the secret. Subsequent launches with a non-empty
// api_keys table are no-ops.
// bootstrapAdminKeyIfNeeded provisions a fresh admin api key the first time
// the daemon boots into an empty database. defaultRateLimit is the
// security.rate_limit_default from config.yaml (falls back to 100/min when
// unset) so operators can lift the limit before first launch without having
// to PATCH the row after the fact.
func bootstrapAdminKeyIfNeeded(ctx context.Context, repo storage.APIKeyRepository, privPath, pubPath string, defaultRateLimit int, log *slog.Logger) error {
	count, err := repo.Count(ctx, storage.APIKeyFilter{})
	if err != nil {
		return fmt.Errorf("count api keys: %w", err)
	}
	if count > 0 {
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	// The apikeys/ subdir holds every API-credential file the operator may
	// touch (bootstrap admin, keys minted via `api-key keygen`, keystores
	// created via `keystore create`). Daemon home is 0700; the parent dir
	// inherits the same lockdown.
	if err := os.MkdirAll(filepath.Dir(privPath), 0700); err != nil {
		return fmt.Errorf("create api-keys dir: %w", err)
	}

	privPEM, err := encodeEd25519PrivPEM(priv)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	pubPEM, err := encodeEd25519PubPEM(pub)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}

	// Write private key first; if it fails we don't want a half-bootstrap.
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		// Roll back the priv key file so the next run retries cleanly.
		_ = os.Remove(privPath)
		return fmt.Errorf("write %s: %w", pubPath, err)
	}

	rateLimit := defaultRateLimit
	if rateLimit <= 0 {
		rateLimit = 100
	}
	now := time.Now()
	key := &types.APIKey{
		ID:           "admin",
		Name:         "admin (bootstrap)",
		PublicKeyHex: hex.EncodeToString(pub),
		RateLimit:    rateLimit,
		Role:         types.RoleAdmin,
		Enabled:      true,
		Source:       types.APIKeySourceBootstrap,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := repo.Create(ctx, key); err != nil {
		// Best-effort rollback of the key files so a retry can succeed.
		_ = os.Remove(privPath)
		_ = os.Remove(pubPath)
		return fmt.Errorf("create admin api_key row: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "[BOOTSTRAP] First-run setup — admin API key created.")
	fmt.Fprintln(os.Stderr, "  Private key file:  "+privPath+"  (chmod 600)")
	fmt.Fprintln(os.Stderr, "  Public key file:   "+pubPath)
	fmt.Fprintln(os.Stderr, "  Public key (hex):  "+hex.EncodeToString(pub))
	fmt.Fprintln(os.Stderr, "  Role:              admin")
	fmt.Fprintln(os.Stderr, "  WARNING: keep "+privPath+" safe; it is the only")
	fmt.Fprintln(os.Stderr, "  credential that can administer this instance.")
	fmt.Fprintln(os.Stderr)

	log.Info("bootstrap admin API key written", "priv", privPath, "pub", pubPath)
	return nil
}

func encodeEd25519PrivPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodeEd25519PubPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
