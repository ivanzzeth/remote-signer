package version

// Version is the unified version string for the remote-signer binary
// and all its subcommands (server, tui, validate, admin).
//
// Declared as a var (not const) so the build pipeline can override it
// via `-ldflags "-X github.com/ivanzzeth/remote-signer/internal/version.Version=<tag>"`.
// Source of truth is the git tag at release time:
//
//   - CI release.yml strips the leading 'v' from GITHUB_REF_NAME and
//     injects it here, so a tag of v0.4.0 produces a binary whose
//     `remote-signer version` reports "0.4.0".
//   - The Makefile uses `git describe --tags --always --dirty`, so a
//     local `make build` after the v0.4.0 tag with one extra commit
//     reports something like "v0.4.0-1-gabc1234"; on a dirty tree it
//     also gets "-dirty".
//
// The "dev" default is only seen when neither path applies — direct
// `go build ./cmd/remote-signer` without ldflags. See GIT.md for the
// full release-versioning convention.
var Version = "dev"
