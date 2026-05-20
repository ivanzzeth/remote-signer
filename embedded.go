// Package remotesigner is the module's root package. Its sole purpose is
// to host the //go:embed directives that bake the daemon's blessed rule
// templates + presets into the binary — a fresh `remote-signer server
// start` then has everything it needs to bootstrap agent rules without
// the operator copying rules/ into their daemon home.
//
// The embed directive can only reference files inside the package
// directory (no `..`), which is why this file lives at the repo root
// rather than under `internal/` — that's the only location from which
// `rules/templates` and `rules/presets` are reachable.
//
// Filesystem layout exposed via fs.FS is the same as on disk
// (`rules/templates/evm/agent.yaml`, etc.), so the file-based Source
// implementations can walk EmbeddedRules with `fs.WalkDir` identically
// to walking `os.DirFS(...)` over a real directory.
package remotesigner

import "embed"

// EmbeddedRules holds the shipped rule catalogue (templates + presets).
// Walk it with the standard io/fs package — registry's
// `NewFSTemplateSource` / `NewFSPresetSource` consume any fs.FS.
//
//go:embed all:rules/templates all:rules/presets
var EmbeddedRules embed.FS
