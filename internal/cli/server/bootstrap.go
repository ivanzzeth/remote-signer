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

	"github.com/ivanzzeth/ethsig/keystore"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// bootstrapAdminKeyIfNeeded checks whether any API keys exist and, if not,
// generates an Ed25519 admin keypair via CreateEnhancedKey, renames the
// resulting keystore to the stable path keystorePath, writes the public
// key to pubPath, and inserts a corresponding api_keys row with
// source="bootstrap".
//
// During bootstrap the operator is prompted on stderr for a new keystore
// password (or it's read from REMOTE_SIGNER_KEYSTORE_PASSWORD). The raw
// Ed25519 private key is never written to disk in plaintext — only the
// encrypted keystore file persists. The daemon itself does NOT need the
// keystore password to start later — admin signature verification uses
// the public-key column on api_keys.
//
// Subsequent launches with a non-empty api_keys table are no-ops.
func bootstrapAdminKeyIfNeeded(ctx context.Context, repo storage.APIKeyRepository, keystoreDir, keystorePath, pubPath string, defaultRateLimit int, log *slog.Logger) error {
	count, err := repo.Count(ctx, storage.APIKeyFilter{})
	if err != nil {
		return fmt.Errorf("count api keys: %w", err)
	}
	if count > 0 {
		return nil
	}

	// If the keystore already exists (partial bootstrap that created the
	// file but not the DB row), we're in a half-done state. The DB being
	// empty while the keystore exists is anomalous; bail.
	if _, err := os.Stat(keystorePath); err == nil {
		log.Warn("admin keystore exists but DB is empty — possible partial bootstrap", "keystore", keystorePath)
		return fmt.Errorf("admin keystore %s exists but the api_keys table is empty; delete the keystore or fix the database", keystorePath)
	}

	// The apikeys/ subdir holds every API-credential file the operator may
	// touch (bootstrap admin, keys minted via `api-key keygen`, keystores
	// created via `keystore create`). Daemon home is 0700; the parent dir
	// inherits the same lockdown.
	if err := os.MkdirAll(keystoreDir, 0700); err != nil {
		return fmt.Errorf("create api-keys dir: %w", err)
	}

	// Prompt for a keystore password at bootstrap time.
	fmt.Fprint(os.Stderr, "[BOOTSTRAP] Admin keystore is being created.\n")
	var password []byte
	envPassword := os.Getenv("REMOTE_SIGNER_KEYSTORE_PASSWORD")
	if envPassword != "" {
		password = []byte(envPassword)
	} else {
		var err error
		password, err = keystore.ReadPasswordWithConfirm(ctx, "Enter admin keystore password")
		if err != nil {
			return fmt.Errorf("read keystore password: %w", err)
		}
	}
	defer keystore.SecureZeroize(password)

	// CreateEnhancedKey generates an Ed25519 keypair internally, encrypts
	// it with the supplied password, and writes the keystore JSON file
	// under a hash-derived filename. We immediately rename it to the
	// canonical, stable path so operators (and the web UI / popup) know
	// exactly which file to point at — no indirection, no pointer files.
	// The returned identifier is the hex-encoded public key.
	identifier, generatedPath, err := keystore.CreateEnhancedKey(
		keystoreDir,
		keystore.KeyTypeEd25519,
		password,
		"admin (bootstrap)",
	)
	if err != nil {
		return fmt.Errorf("create encrypted admin keystore: %w", err)
	}
	if err := os.Rename(generatedPath, keystorePath); err != nil {
		// If rename fails the keystore exists at the hash-named path but
		// the daemon won't find it on next start — clean up to avoid
		// the partial-bootstrap trap above.
		_ = os.Remove(generatedPath)
		return fmt.Errorf("rename admin keystore to %s: %w", keystorePath, err)
	}

	// The identifier from CreateEnhancedKey is the hex-encoded public key.
	// Parse it so we can write the public PEM and populate the DB record.
	pubHex := identifier
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return fmt.Errorf("decode keystore identifier as hex public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("unexpected public key size from keystore identifier: %d", len(pubBytes))
	}
	pub := ed25519.PublicKey(pubBytes)

	// Write public key PEM (non-secret, readable metadata).
	pubPEM, err := encodeEd25519PubPEM(pub)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("write %s: %w", pubPath, err)
	}

	rateLimit := defaultRateLimit
	if rateLimit <= 0 {
		rateLimit = 100
	}
	now := time.Now()
	apiKey := &types.APIKey{
		ID:           "admin",
		Name:         "admin (bootstrap)",
		PublicKeyHex: pubHex,
		RateLimit:    rateLimit,
		Role:         types.RoleAdmin,
		Enabled:      true,
		Source:       types.APIKeySourceBootstrap,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := repo.Create(ctx, apiKey); err != nil {
		_ = os.Remove(keystorePath)
		_ = os.Remove(pubPath)
		return fmt.Errorf("create admin api_key row: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "[BOOTSTRAP] First-run setup — admin API key created.")
	fmt.Fprintln(os.Stderr, "  Keystore file:      "+keystorePath)
	fmt.Fprintln(os.Stderr, "  Public key file:    "+pubPath)
	fmt.Fprintln(os.Stderr, "  Public key (hex):   "+pubHex)
	fmt.Fprintln(os.Stderr, "  Role:               admin")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  The keystore at the path above is the authoritative copy of")
	fmt.Fprintln(os.Stderr, "  the private key. CLI tools open it directly when you pass")
	fmt.Fprintln(os.Stderr, "  `--api-key-id admin` with no `--api-key-file` /")
	fmt.Fprintln(os.Stderr, "  `--api-key-keystore`. Password from REMOTE_SIGNER_KEYSTORE_PASSWORD")
	fmt.Fprintln(os.Stderr, "  or an interactive prompt. The daemon itself does NOT need the")
	fmt.Fprintln(os.Stderr, "  password on subsequent starts.")
	fmt.Fprintln(os.Stderr)

	log.Info("bootstrap admin API key written", "keystore", keystorePath, "pub", pubPath)
	return nil
}

// bootstrapAgentKeyIfNeeded provisions a fresh agent Ed25519 keypair the first
// time the daemon boots (when no agent key with id="agent" exists yet).
// Unlike the admin key check — which guards on "any key in the table" — this
// creates the agent key independently so existing admin keys do not block it.
//
// The agent keypair is written to <home>/agent.key.priv (0600) and
// <home>/agent.key.pub (0644) under the apikeys/ subdir, and an api_keys row
// with id="agent", role="agent", source="bootstrap" is inserted.
func bootstrapAgentKeyIfNeeded(ctx context.Context, repo storage.APIKeyRepository, privPath, pubPath string, defaultRateLimit int, log *slog.Logger) error {
	existing, err := repo.Get(ctx, "agent")
	if err != nil && !types.IsNotFound(err) {
		return fmt.Errorf("get agent api key: %w", err)
	}
	if existing != nil {
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 keypair: %w", err)
	}

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

	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		_ = os.Remove(privPath)
		return fmt.Errorf("write %s: %w", pubPath, err)
	}

	rateLimit := defaultRateLimit
	if rateLimit <= 0 {
		rateLimit = 100
	}
	now := time.Now()
	key := &types.APIKey{
		ID:           "agent",
		Name:         "agent (bootstrap)",
		PublicKeyHex: hex.EncodeToString(pub),
		RateLimit:    rateLimit,
		Role:         types.RoleAgent,
		Enabled:      true,
		Source:       types.APIKeySourceBootstrap,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := repo.Create(ctx, key); err != nil {
		_ = os.Remove(privPath)
		_ = os.Remove(pubPath)
		return fmt.Errorf("create agent api_key row: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "[BOOTSTRAP] First-run setup — agent API key created.")
	fmt.Fprintln(os.Stderr, "  Private key file:  "+privPath+"  (chmod 600)")
	fmt.Fprintln(os.Stderr, "  Public key file:   "+pubPath)
	fmt.Fprintln(os.Stderr, "  Public key (hex):  "+hex.EncodeToString(pub))
	fmt.Fprintln(os.Stderr, "  Role:              agent")
	fmt.Fprintln(os.Stderr, "  This key is used by automated agents.")
	fmt.Fprintln(os.Stderr)

	log.Info("bootstrap agent API key written", "priv", privPath, "pub", pubPath)
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
