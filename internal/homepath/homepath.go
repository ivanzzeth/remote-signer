// Package homepath resolves the remote-signer per-user home directory and the
// default paths derived from it (config.yaml, sqlite DB, bootstrap key files).
//
// Resolution order for the home directory:
//  1. $REMOTE_SIGNER_HOME
//  2. $HOME/.remote-signer
//
// EnsureHome creates the directory with 0700 permissions on first use; the
// daemon expects to own it exclusively because it writes the bootstrap admin
// private key there.
package homepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	configFile             = "config.yaml"
	sqliteFile             = "remote-signer.db"
	apiKeysSubdir          = "apikeys"
	signerKeystoresSubdir  = "keystores"
	adminPrivKeyFile       = "admin.key.priv"
	adminPubKeyFile        = "admin.key.pub"
	adminKeystoreFile      = "admin.keystore.json"
	agentPrivKeyFile       = "agent.key.priv"
	agentPubKeyFile        = "agent.key.pub"
	envHome                = "REMOTE_SIGNER_HOME"
	envConfig              = "REMOTE_SIGNER_CONFIG"
)

// Home returns the remote-signer per-user home directory path without creating it.
func Home() (string, error) {
	if h := os.Getenv(envHome); h != "" {
		return h, nil
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(userHome, ".remote-signer"), nil
}

// EnsureHome resolves the home dir and creates it with 0700 if it does not exist.
func EnsureHome() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(h, 0700); err != nil {
		return "", fmt.Errorf("create %s: %w", h, err)
	}
	return h, nil
}

// ConfigPath returns the default config.yaml path inside the home dir.
func ConfigPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, configFile), nil
}

// SQLitePath returns the default SQLite database path inside the home dir.
func SQLitePath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, sqliteFile), nil
}

// DefaultSQLiteDSN returns the gorm DSN for the home-dir SQLite file with WAL
// and a 5s busy timeout enabled — sane defaults for a single-instance setup.
func DefaultSQLiteDSN() (string, error) {
	p, err := SQLitePath()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000", p), nil
}

// APIKeysDir returns the directory that holds the Ed25519 PEM/keystore files
// callers use to authenticate to the remote-signer API. The bootstrap admin
// keypair, anything minted via `api-key keygen`, and keystores created via
// `api-key keystore create` all share this location.
func APIKeysDir() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, apiKeysSubdir), nil
}

// SignerKeystoresDir returns the directory that holds encrypted keystores
// for chain-side signing keys (typically secp256k1 for EVM). The daemon
// writes here when an admin creates a signer through the HTTP API; the
// top-level `keystore` CLI defaults its --dir flag here so the same path
// works for both inspection and rotation.
func SignerKeystoresDir() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, signerKeystoresSubdir), nil
}

// AdminKeyPaths returns the bootstrap admin private/public key file paths.
// They live under APIKeysDir so the operator only needs to memorise a single
// directory ($HOME/.remote-signer/apikeys) for every credential.
func AdminKeyPaths() (privPath, pubPath string, err error) {
	dir, err := APIKeysDir()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(dir, adminPrivKeyFile), filepath.Join(dir, adminPubKeyFile), nil
}

// AdminKeystorePath returns the canonical path of the encrypted admin
// keystore JSON file. Bootstrap writes it here; every consumer (daemon,
// CLI, web UI, popup) reads it from here. No pointer files, no
// hash-derived filenames the operator has to memorise.
func AdminKeystorePath() (string, error) {
	dir, err := APIKeysDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, adminKeystoreFile), nil
}

// AgentKeyPaths returns the bootstrap agent private/public key file paths.
// They live under APIKeysDir so the operator only needs to memorise a single
// directory ($HOME/.remote-signer/apikeys) for every credential.
func AgentKeyPaths() (privPath, pubPath string, err error) {
	dir, err := APIKeysDir()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(dir, agentPrivKeyFile), filepath.Join(dir, agentPubKeyFile), nil
}

// ResolveConfigPath determines which config.yaml the server should load.
//   - flagPath: from -config flag; if non-empty, always wins
//   - $REMOTE_SIGNER_CONFIG: explicit env override
//   - ~/.remote-signer/config.yaml: per-user default
//   - ./config.yaml: project-local fallback (legacy)
//
// Returns the chosen path AND whether that file already exists. Caller decides
// whether to write a default when !exists.
func ResolveConfigPath(flagPath string) (path string, exists bool, err error) {
	if flagPath != "" {
		if _, err := os.Stat(flagPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return flagPath, false, nil
			}
			return "", false, err
		}
		return flagPath, true, nil
	}
	if env := os.Getenv(envConfig); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, true, nil
		} else if errors.Is(err, os.ErrNotExist) {
			return env, false, nil
		} else {
			return "", false, err
		}
	}
	home, err := ConfigPath()
	if err != nil {
		return "", false, err
	}
	if _, err := os.Stat(home); err == nil {
		return home, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	if _, err := os.Stat("./config.yaml"); err == nil {
		abs, _ := filepath.Abs("./config.yaml")
		return abs, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	// Nothing on disk; recommend writing to home.
	return home, false, nil
}
