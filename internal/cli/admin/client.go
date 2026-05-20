package admin

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/ivanzzeth/remote-signer/internal/homepath"
	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/spf13/cobra"
)

// Auth flag variables (bound to persistent flags on rootCmd)
var (
	flagURL              string
	flagAPIKeyID         string
	flagAPIKeyFile       string
	flagAPIKeyKeystore   string
	flagAPIKeyPasswordEnv string
	flagTLSCA            string
	flagTLSCert          string
	flagTLSKey           string
	flagTLSSkipVerify    bool
	flagOutputFormat     string
	flagJSON             bool
)

// registerAuthFlags adds persistent auth flags to the root command.
// Supports environment variables: REMOTE_SIGNER_URL, REMOTE_SIGNER_API_KEY_ID, REMOTE_SIGNER_API_KEY_FILE,
// REMOTE_SIGNER_TLS_CA, REMOTE_SIGNER_TLS_CERT, REMOTE_SIGNER_TLS_KEY
func registerAuthFlags(rootCmd *cobra.Command) {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagURL, "url", getEnvOrDefault("REMOTE_SIGNER_URL", "https://localhost:8548"), "Remote signer server URL (env: REMOTE_SIGNER_URL)")
	pf.StringVar(&flagAPIKeyID, "api-key-id", os.Getenv("REMOTE_SIGNER_API_KEY_ID"), "API key ID for authentication (env: REMOTE_SIGNER_API_KEY_ID)")
	pf.StringVar(&flagAPIKeyFile, "api-key-file", os.Getenv("REMOTE_SIGNER_API_KEY_FILE"), "Path to Ed25519 private key PEM file (env: REMOTE_SIGNER_API_KEY_FILE)")
	pf.StringVar(&flagAPIKeyKeystore, "api-key-keystore", os.Getenv("REMOTE_SIGNER_API_KEY_KEYSTORE"), "Path to Ed25519 encrypted keystore file (mutually exclusive with --api-key-file) (env: REMOTE_SIGNER_API_KEY_KEYSTORE)")
	pf.StringVar(&flagAPIKeyPasswordEnv, "api-key-password-env", "", "Environment variable name containing the keystore password (for CI; default: interactive prompt)")
	pf.StringVar(&flagTLSCA, "tls-ca", os.Getenv("REMOTE_SIGNER_TLS_CA"), "CA certificate for TLS verification (env: REMOTE_SIGNER_TLS_CA)")
	pf.StringVar(&flagTLSCert, "tls-cert", os.Getenv("REMOTE_SIGNER_TLS_CERT"), "Client certificate for mTLS (env: REMOTE_SIGNER_TLS_CERT)")
	pf.StringVar(&flagTLSKey, "tls-key", os.Getenv("REMOTE_SIGNER_TLS_KEY"), "Client key for mTLS (env: REMOTE_SIGNER_TLS_KEY)")
	pf.BoolVar(&flagTLSSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (testing only)")
	pf.StringVarP(&flagOutputFormat, "output", "o", "table", "Output format: table, json, yaml")
	pf.BoolVar(&flagJSON, "json", false, "Machine-readable JSON output (sets -o json; PRD agent output)")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if flagJSON {
			flagOutputFormat = "json"
		}
	}
}

// getEnvOrDefault returns environment variable value or default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

// newClientFromFlags creates a pkg/client.Client using the persistent auth flags.
func newClientFromFlags(cmd *cobra.Command) (*client.Client, error) {
	if flagAPIKeyID == "" {
		return nil, fmt.Errorf("--api-key-id is required")
	}
	if flagAPIKeyFile != "" && flagAPIKeyKeystore != "" {
		return nil, fmt.Errorf("--api-key-file and --api-key-keystore are mutually exclusive")
	}

	keystorePath := flagAPIKeyKeystore
	pemPath := flagAPIKeyFile

	// Auto-discover the credential when neither flag is set. The daemon's
	// bootstrap writes the admin keystore pointer file at the conventional
	// path; for the admin id we read that pointer to locate the keystore
	// JSON. For other ids we look for either a sibling keystore ptr or a
	// legacy <id>.key.priv PEM. This is the "just works" path the operator
	// wants — `--api-key-id admin` is enough on a daemon home set up by
	// the post-cleanup binary.
	if keystorePath == "" && pemPath == "" {
		discovered, discErr := discoverDefaultCredential(flagAPIKeyID)
		if discErr != nil {
			return nil, discErr
		}
		if discovered.keystorePath != "" {
			keystorePath = discovered.keystorePath
		} else if discovered.pemPath != "" {
			pemPath = discovered.pemPath
		} else {
			return nil, fmt.Errorf(
				"no credential found for --api-key-id %q; pass --api-key-keystore or --api-key-file, or bootstrap the daemon to write one to ~/.remote-signer/apikeys",
				flagAPIKeyID,
			)
		}
	}

	var privKey ed25519.PrivateKey
	if keystorePath != "" {
		key, err := loadEd25519FromKeystore(cmd, keystorePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load key from keystore %s: %w", keystorePath, err)
		}
		privKey = key
	} else {
		key, err := loadEd25519PrivateKey(pemPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key from %s: %w", pemPath, err)
		}
		privKey = key
	}

	cfg := client.Config{
		BaseURL:       flagURL,
		APIKeyID:      flagAPIKeyID,
		PrivateKey:    privKey,
		TLSCAFile:     flagTLSCA,
		TLSCertFile:   flagTLSCert,
		TLSKeyFile:    flagTLSKey,
		TLSSkipVerify: flagTLSSkipVerify,
	}

	return client.NewClient(cfg)
}

// loadEd25519FromKeystore decrypts an ethsig encrypted keystore to get the Ed25519 private key.
func loadEd25519FromKeystore(cmd *cobra.Command, keystorePath string) (ed25519.PrivateKey, error) {
	password, err := resolveKeystorePassword(cmd)
	if err != nil {
		return nil, fmt.Errorf("resolve keystore password: %w", err)
	}
	defer keystore.SecureZeroize(password)

	seedBytes, err := keystore.ExportEnhancedKey(keystorePath, password, keystore.KeyFormatHex)
	if err != nil {
		return nil, fmt.Errorf("decrypt keystore: %w", err)
	}
	defer keystore.SecureZeroize(seedBytes)

	// seedBytes is hex-encoded; parse back to raw bytes
	rawSeed, err := keystore.ParseKeyInput(seedBytes, keystore.KeyFormatHex, keystore.KeyTypeEd25519)
	if err != nil {
		return nil, fmt.Errorf("parse seed from keystore: %w", err)
	}
	defer keystore.SecureZeroize(rawSeed)

	return ed25519.NewKeyFromSeed(rawSeed), nil
}

// resolveKeystorePassword gets the password using the documented precedence:
//
//  1. --api-key-password-env <NAME>  (explicit operator-named env var)
//  2. REMOTE_SIGNER_KEYSTORE_PASSWORD env var (the daemon's own convention,
//     shared across CLI + daemon so an operator can `export` it once and
//     have everything pick it up without per-tool flags)
//  3. interactive prompt on stderr
//
// Steps 1 and 2 are skipped silently when their inputs are absent; only
// the explicit --api-key-password-env path errors on missing env var.
func resolveKeystorePassword(cmd *cobra.Command) ([]byte, error) {
	if flagAPIKeyPasswordEnv != "" {
		envVal := os.Getenv(flagAPIKeyPasswordEnv)
		if envVal == "" {
			return nil, fmt.Errorf("environment variable %s is empty or not set", flagAPIKeyPasswordEnv)
		}
		return []byte(envVal), nil
	}
	if envVal := os.Getenv("REMOTE_SIGNER_KEYSTORE_PASSWORD"); envVal != "" {
		return []byte(envVal), nil
	}
	fmt.Fprint(os.Stderr, "Enter keystore password: ")
	return keystore.ReadSecret(cmd.Context())
}

// discoveredCredential captures whichever credential file the auto-discovery
// path found for the given api-key id. Exactly one of keystorePath / pemPath
// is populated when err == nil; both empty means nothing was found at the
// expected locations.
type discoveredCredential struct {
	keystorePath string
	pemPath      string
}

// discoverDefaultCredential finds the credential file for an api-key id by
// walking the daemon's conventional layout under
// $HOME/.remote-signer/apikeys/:
//
//   - For "admin": read admin.key.keystore (the bootstrap ptr file) and use
//     the path inside it. This is the post-cleanup default — the daemon no
//     longer exports admin.key.priv on startup.
//   - Fallback for any id: look for <id>.key.priv (legacy PEM). Used by
//     "agent" (which is still PEM-only) and by operators who haven't yet
//     migrated their admin key to keystore format.
//
// Returns zero discoveredCredential + nil err when nothing matched — the
// caller should treat that as "user must pass an explicit flag".
func discoverDefaultCredential(apiKeyID string) (discoveredCredential, error) {
	if apiKeyID == "admin" {
		ptrPath, err := homepath.AdminKeystorePtrPath()
		if err == nil {
			if data, readErr := os.ReadFile(ptrPath); readErr == nil {
				keystorePath := strings.TrimSpace(string(data))
				if keystorePath != "" {
					if _, statErr := os.Stat(keystorePath); statErr == nil {
						return discoveredCredential{keystorePath: keystorePath}, nil
					}
				}
			}
		}
	}

	// Generic PEM fallback: <api-key-id>.key.priv inside the apikeys dir.
	apikeysDir, err := homepath.APIKeysDir()
	if err != nil {
		return discoveredCredential{}, nil
	}
	pemPath := filepath.Join(apikeysDir, apiKeyID+".key.priv")
	if _, statErr := os.Stat(pemPath); statErr == nil {
		return discoveredCredential{pemPath: pemPath}, nil
	}
	return discoveredCredential{}, nil
}

// loadEd25519PrivateKey reads a PEM file and extracts the Ed25519 private key.
func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath) // #nosec G304 -- user-provided CLI flag, path cleaned
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
	}
	return edKey, nil
}
