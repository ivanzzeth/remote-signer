package server

import (
	"log/slog"
	"os"
)

// unlockAdminKeystoreIfNeeded historically read the admin keystore pointer
// file, prompted for the keystore password, and exported a plaintext PEM
// at privPath so CLI tools that hardcoded --api-key-file ~/.remote-signer/
// apikeys/admin.key.priv kept working. That exposed the unencrypted seed
// on disk for the daemon's entire lifetime — a regression versus the
// at-rest encryption the keystore was supposed to provide. Removed.
//
// What replaces it:
//
//   - The daemon itself never needed the admin private key; it verifies
//     API request signatures using the public-key column of api_keys
//     (no signing happens server-side for admin auth).
//   - CLI tools default to opening the keystore directly via the ptr
//     file. See internal/cli/admin/client.go's resolveAuth() — passing
//     `--api-key-id admin` with no `--api-key-file` / `--api-key-keystore`
//     auto-discovers the keystore. Password comes from
//     REMOTE_SIGNER_KEYSTORE_PASSWORD or an interactive prompt.
//   - The web UI accepts the keystore JSON directly on first onboarding
//     and stores it as-is in localStorage (see web/src/lib/keystore.ts).
//
// This function is kept as a no-op so the call site in run.go doesn't
// have to change again the next time we revisit this; if a stale
// admin.key.priv exists from a pre-cleanup daemon run, we proactively
// remove it on startup so a stray plaintext copy can't linger.
func unlockAdminKeystoreIfNeeded(ptrPath, privPath string, log *slog.Logger) (func(), error) {
	// Best-effort cleanup of any stale admin PEM left over from a
	// pre-cleanup daemon binary. We only do this when a pointer file
	// exists (i.e. the operator IS on the keystore format); legacy
	// PEM-only deployments are untouched.
	if _, err := os.Stat(ptrPath); err == nil {
		if data, readErr := os.ReadFile(privPath); readErr == nil {
			for i := range data {
				data[i] = 0
			}
			_ = os.WriteFile(privPath, data, 0600)
			if removeErr := os.Remove(privPath); removeErr != nil {
				log.Warn("failed to remove stale admin PEM", "path", privPath, "error", removeErr)
			} else {
				log.Info("removed stale plaintext admin PEM (keystore is the authoritative source)", "path", privPath)
			}
		}
	}
	_ = ptrPath
	return func() {}, nil
}
