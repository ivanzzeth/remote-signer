// Package bootstrap holds the shared types used by every entry point that
// can complete the first-run admin-keystore setup:
//
//   - internal/cli/server (the startup-time env-var path).
//   - internal/api/handler (the HTTP /api/v1/bootstrap/* path consumed by
//     the web UI).
//   - cmd/remote-signer's `api-key bootstrap` subcommand (the CLI path).
//
// The package is intentionally leaf-level — no other internal package
// imports it transitively — so it can be referenced from both the API
// layer (which mustn't depend on cli/server) and the CLI layer.
package bootstrap

import (
	"context"
	"errors"
)

// ErrAdminAlreadyExists is the sentinel that signals "the bootstrap window
// has closed". The HTTP handler maps this to 410 Gone so a client racing a
// second bootstrap attempt gets an actionable response. The CLI subcommand
// maps it to a non-zero exit with a clear message.
var ErrAdminAlreadyExists = errors.New("admin api key already exists; bootstrap window has closed")

// AdminResult is what an AdminCreator reports back on success.
//
// KeystoreJSON is the encrypted keystore content read back from disk
// immediately after creation. The web bootstrap flow needs it to
// transition seamlessly from "set a password" to a logged-in session
// without forcing the operator to manually copy a file off the daemon's
// home directory (which, in a container, isn't even accessible from the
// browser machine). The CLI subcommand just ignores this field.
//
// The JSON is the same scrypt-encrypted blob already on disk; transmitting
// it back over the same channel that just carried the password is no
// weaker than the disk write itself, and the field never contains the
// plaintext key.
type AdminResult struct {
	KeystorePath string `json:"keystore_path"`
	PubKeyPath   string `json:"pub_key_path"`
	PubKeyHex    string `json:"public_key_hex"`
	KeystoreJSON string `json:"keystore_json,omitempty"`
}

// AdminCreator is the callback the HTTP handler uses to perform the
// actual admin keystore creation. Wiring constructs the closure at daemon
// boot with the keystore directory, paths, and default rate limit already
// curried in, so handler.NewBootstrapHandler only sees a context + password.
type AdminCreator func(ctx context.Context, password []byte) (*AdminResult, error)
