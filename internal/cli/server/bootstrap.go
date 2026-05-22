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

	"github.com/ivanzzeth/remote-signer/internal/bootstrap"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// CreateAdminKeystore generates an Ed25519 keypair encrypted with the given
// password, writes the encrypted keystore + public-key PEM under the daemon
// home, and inserts the matching api_keys row.
//
// Returns ErrAdminAlreadyExists if any API key already exists (the bootstrap
// window has already closed). Returns ErrAdminAlreadyExists also if the
// keystore file is already present on disk (partial bootstrap from a
// previous half-done attempt — operator needs to investigate manually).
//
// This function is shared by:
//
//   - The env-var startup path (bootstrapAdminKeyIfNeeded below)
//   - The HTTP handler (POST /api/v1/bootstrap/admin)
//   - The CLI subcommand (remote-signer api-key bootstrap)
//
// The raw Ed25519 private key never reaches disk in plaintext — only the
// encrypted keystore file persists. The daemon does NOT need the keystore
// password on subsequent starts; admin signature verification uses the
// public-key column in api_keys.
func CreateAdminKeystore(
	ctx context.Context,
	repo storage.APIKeyRepository,
	keystoreDir, keystorePath, pubPath string,
	password []byte,
	defaultRateLimit int,
	log *slog.Logger,
) (*bootstrap.AdminResult, error) {
	// Specifically check for an existing id="admin" row, not "any api
	// key". The agent api key is provisioned unconditionally by
	// bootstrapAgentKeyIfNeeded at first start, so a count-based check
	// would mistakenly report "already configured" once the agent had
	// landed even though no admin exists yet.
	existing, err := repo.Get(ctx, "admin")
	if err != nil && !types.IsNotFound(err) {
		return nil, fmt.Errorf("get admin api key: %w", err)
	}
	if existing != nil {
		return nil, bootstrap.ErrAdminAlreadyExists
	}

	// Keystore on disk with no DB row = partial bootstrap. Refuse rather
	// than risk creating a second keystore that diverges from the file
	// the next start will reuse.
	if _, err := os.Stat(keystorePath); err == nil {
		log.Warn("admin keystore exists but DB is empty — possible partial bootstrap", "keystore", keystorePath)
		return nil, fmt.Errorf("admin keystore %s exists but the api_keys table is empty; delete the keystore or fix the database", keystorePath)
	}

	if err := os.MkdirAll(keystoreDir, 0700); err != nil {
		return nil, fmt.Errorf("create api-keys dir: %w", err)
	}

	// CreateEnhancedKey generates an Ed25519 keypair internally, encrypts
	// it with the supplied password, and writes the keystore JSON file
	// under a hash-derived filename. We rename it to the canonical stable
	// path so operators (and the web UI / popup / CLI) know exactly which
	// file to point at. The returned identifier is the hex-encoded public
	// key.
	identifier, generatedPath, err := keystore.CreateEnhancedKey(
		keystoreDir,
		keystore.KeyTypeEd25519,
		password,
		"admin (bootstrap)",
	)
	if err != nil {
		return nil, fmt.Errorf("create encrypted admin keystore: %w", err)
	}
	if err := os.Rename(generatedPath, keystorePath); err != nil {
		_ = os.Remove(generatedPath)
		return nil, fmt.Errorf("rename admin keystore to %s: %w", keystorePath, err)
	}

	pubBytes, err := hex.DecodeString(identifier)
	if err != nil {
		return nil, fmt.Errorf("decode keystore identifier as hex public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected public key size from keystore identifier: %d", len(pubBytes))
	}
	pub := ed25519.PublicKey(pubBytes)

	pubPEM, err := encodeEd25519PubPEM(pub)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return nil, fmt.Errorf("write %s: %w", pubPath, err)
	}

	rateLimit := defaultRateLimit
	if rateLimit <= 0 {
		rateLimit = 10000
	}
	now := time.Now()
	apiKey := &types.APIKey{
		ID:           "admin",
		Name:         "admin (bootstrap)",
		PublicKeyHex: identifier,
		RateLimit:    rateLimit,
		Role:         types.RoleAdmin,
		Enabled:      true,
		Source:       types.APIKeySourceBootstrap,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := repo.Create(ctx, apiKey); err != nil {
		// Roll back the on-disk files so a retry can re-create cleanly
		// rather than tripping the partial-bootstrap guard.
		_ = os.Remove(keystorePath)
		_ = os.Remove(pubPath)
		return nil, fmt.Errorf("create admin api_key row: %w", err)
	}

	log.Info("bootstrap admin API key written",
		"keystore", keystorePath,
		"pub", pubPath,
		"pub_hex", identifier,
	)
	// Read the just-written encrypted keystore back so the web UI can
	// store it client-side and chain straight into a logged-in session.
	// See bootstrap.AdminResult.KeystoreJSON for rationale.
	keystoreBlob, readErr := os.ReadFile(keystorePath)
	if readErr != nil {
		log.Warn("admin keystore created but couldn't be read back for response", "keystore", keystorePath, "err", readErr)
		// Non-fatal: the keystore is on disk; the CLI subcommand only
		// uses the paths. The web flow will detect the missing field
		// and fall back to "please reload and log in manually".
	}

	return &bootstrap.AdminResult{
		KeystorePath: keystorePath,
		PubKeyPath:   pubPath,
		PubKeyHex:    identifier,
		KeystoreJSON: string(keystoreBlob),
	}, nil
}

// bootstrapAdminKeyIfNeeded is the startup-time wrapper. Behaviour depends
// on the environment:
//
//   - api_keys non-empty → no-op (subsequent boots).
//   - api_keys empty, REMOTE_SIGNER_KEYSTORE_PASSWORD set → inline bootstrap.
//     The daemon comes up fully ready.
//   - api_keys empty, no env var → "soft start". The daemon comes up
//     listening on HTTP, but no admin exists yet. Logs a WARN telling the
//     operator they can complete bootstrap via web UI or
//     `remote-signer api-key bootstrap`. Returns nil so the caller can
//     proceed to start the HTTP server.
//
// Removed: the TTY interactive prompt that used to run here. It was the
// surprising path — same command behaved differently based on whether
// stdin was a terminal, blocked daemon startup waiting for input, and had
// platform-specific edge cases (the recent Windows cross-compile fix for
// ethsig's password helper). With three converging non-blocking paths
// (env / web / CLI), the TTY prompt doesn't earn its complexity.
func bootstrapAdminKeyIfNeeded(
	ctx context.Context,
	repo storage.APIKeyRepository,
	keystoreDir, keystorePath, pubPath string,
	defaultRateLimit int,
	log *slog.Logger,
) error {
	// Check for the specific id="admin" row, not "any api key". See the
	// note in CreateAdminKeystore for why the count-based check would
	// race with the agent bootstrap.
	existing, err := repo.Get(ctx, "admin")
	if err != nil && !types.IsNotFound(err) {
		return fmt.Errorf("get admin api key: %w", err)
	}
	if existing != nil {
		return nil
	}

	envPassword := os.Getenv("REMOTE_SIGNER_KEYSTORE_PASSWORD")
	if envPassword == "" {
		// Soft start. Daemon will accept POST /api/v1/bootstrap/admin
		// to finish the job; until then it has no admin credential.
		log.Warn(
			"bootstrap pending — daemon started without an admin API key. "+
				"Complete setup via the web UI at /, run `remote-signer api-key bootstrap`, "+
				"or set REMOTE_SIGNER_KEYSTORE_PASSWORD and restart.",
			"keystore_target", keystorePath,
		)
		return nil
	}

	password := []byte(envPassword)
	defer keystore.SecureZeroize(password)

	res, err := CreateAdminKeystore(ctx, repo, keystoreDir, keystorePath, pubPath, password, defaultRateLimit, log)
	if err != nil {
		return fmt.Errorf("bootstrap admin (env): %w", err)
	}

	// Operator-facing summary, matched to the previous wording so anyone
	// already familiar with the daemon's first-run output recognises it.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "[BOOTSTRAP] First-run setup — admin API key created.")
	fmt.Fprintln(os.Stderr, "  Keystore file:      "+res.KeystorePath)
	fmt.Fprintln(os.Stderr, "  Public key file:    "+res.PubKeyPath)
	fmt.Fprintln(os.Stderr, "  Public key (hex):   "+res.PubKeyHex)
	fmt.Fprintln(os.Stderr, "  Role:               admin")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  The keystore at the path above is the authoritative copy of")
	fmt.Fprintln(os.Stderr, "  the private key. CLI tools open it directly when you pass")
	fmt.Fprintln(os.Stderr, "  `--api-key-id admin` with no `--api-key-file` /")
	fmt.Fprintln(os.Stderr, "  `--api-key-keystore`. Password from REMOTE_SIGNER_KEYSTORE_PASSWORD")
	fmt.Fprintln(os.Stderr, "  or an interactive prompt. The daemon itself does NOT need the")
	fmt.Fprintln(os.Stderr, "  password on subsequent starts.")
	fmt.Fprintln(os.Stderr)

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
		rateLimit = 10000
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
