package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/ivanzzeth/ethsig/keystore"
)

// unlockAdminKeystoreIfNeeded checks whether an admin keystore pointer file
// exists and, if so, reads the actual keystore path from it, prompts the
// operator for the password, and exports the Ed25519 key as a PEM file at
// privPath so CLI tools (the Go client, web frontend) can use it for
// request signing during the daemon's lifetime.
//
// If the PEM file already exists (e.g. the daemon was restarted within the
// same filesystem and the key was already exported), this is a no-op.
// Callers should defer the returned cleanup function to zero and remove
// the PEM on shutdown.
//
// The password may be supplied via the REMOTE_SIGNER_ADMIN_PASSWORD
// environment variable for non-interactive deployments. When the env var
// is set, the function does not prompt on stderr.
func unlockAdminKeystoreIfNeeded(ptrPath, privPath string, log *slog.Logger) (func(), error) {
	// If no pointer file exists, there is nothing to unlock (admin bootstrapping
	// using the old PEM format, or the daemon has not been bootstrapped yet).
	if _, err := os.Stat(ptrPath); os.IsNotExist(err) {
		return func() {}, nil
	} else if err != nil {
		return nil, fmt.Errorf("stat admin keystore pointer %s: %w", ptrPath, err)
	}

	// Read the keystore path from the pointer file.
	ptrData, err := os.ReadFile(ptrPath)
	if err != nil {
		return nil, fmt.Errorf("read admin keystore pointer %s: %w", ptrPath, err)
	}
	keystorePath := strings.TrimSpace(string(ptrData))
	if keystorePath == "" {
		return nil, fmt.Errorf("admin keystore pointer %s is empty", ptrPath)
	}

	// Verify the keystore file actually exists.
	if _, err := os.Stat(keystorePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("admin keystore %s (from pointer %s) not found", keystorePath, ptrPath)
	} else if err != nil {
		return nil, fmt.Errorf("stat admin keystore %s: %w", keystorePath, err)
	}

	// If the PEM already exists, no unlock needed — the key was already
	// exported in this or a previous session.
	if _, err := os.Stat(privPath); err == nil {
		log.Debug("admin PEM already exists, skipping unlock", "priv", privPath)
		return func() {}, nil
	}

	var password []byte
	envPassword := os.Getenv("REMOTE_SIGNER_KEYSTORE_PASSWORD")
	if envPassword == "" {
		envPassword = os.Getenv("REMOTE_SIGNER_ADMIN_PASSWORD")
	}
	if envPassword != "" {
		password = []byte(envPassword)
	} else {
		fmt.Fprint(os.Stderr, "Enter admin keystore password: ")
		var err error
		password, err = keystore.ReadSecret(context.Background())
		if err != nil {
			return nil, fmt.Errorf("read admin keystore password: %w", err)
		}
		fmt.Fprintln(os.Stderr)
	}
	defer keystore.SecureZeroize(password)

	// Decrypt and export the Ed25519 private key as PEM.
	privPEM, err := keystore.ExportEnhancedKey(keystorePath, password, keystore.KeyFormatPEM)
	if err != nil {
		return nil, fmt.Errorf("unlock admin keystore (wrong password?): %w", err)
	}

	// Write the PEM to disk so CLI tools can find it at the expected path.
	if err := os.MkdirAll(filepath.Dir(privPath), 0700); err != nil {
		return nil, fmt.Errorf("create api-keys dir: %w", err)
	}
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("write %s: %w", privPath, err)
	}

	log.Info("admin keystore unlocked", "priv", privPath)

	// Log the public key info for operator reference.
	info, err := keystore.GetEnhancedKeyInfo(keystorePath)
	if err == nil {
		if len(info.Identifier) >= 16 {
			log.Info("admin keystore info", "identifier", info.Identifier[:16]+"...", "label", info.Label)
		} else {
			log.Info("admin keystore info", "identifier", info.Identifier, "label", info.Label)
		}
	}
	fmt.Fprintf(os.Stderr, "[STARTUP] Admin keystore unlocked.\n")

	// Return a cleanup function that zeros and removes the PEM on shutdown.
	cleanup := func() {
		if _, statErr := os.Stat(privPath); os.IsNotExist(statErr) {
			return
		}
		data, readErr := os.ReadFile(privPath)
		if readErr == nil {
			for i := range data {
				data[i] = 0
			}
			_ = os.WriteFile(privPath, data, 0600)
		}
		if removeErr := os.Remove(privPath); removeErr != nil {
			log.Warn("failed to remove admin PEM on shutdown", "error", removeErr)
		} else {
			log.Debug("admin PEM cleaned up on shutdown")
		}
	}

	return cleanup, nil
}
