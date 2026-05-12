package version

// Version is the unified version string for the remote-signer binary
// and all its subcommands (server, tui, validate, admin).
//
// Bump on every release. Previously this was tracked separately in each
// cmd/<name>/main.go; consolidated to a single source of truth as part of
// the v0.3.0 single-binary refactor.
const Version = "0.3.0-dev"
