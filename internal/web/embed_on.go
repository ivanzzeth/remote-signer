//go:build embed_web

// Package web — embed_on variant. Selected by `-tags embed_web` (set by
// the Makefile's `build-embed` target and the release CI). Bakes the Vite
// build artifacts under ./dist into the binary, so the daemon serves the
// full operator UI off the embedded FS with no on-disk dependency at
// runtime.
//
// The companion file embed_off.go (no tag) takes over when this tag is
// absent and serves a small placeholder explaining how to get the real UI.
// Both files export the same `Dist()` symbol so the rest of the package
// (handler.go) doesn't know which variant is active.

package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var bundle embed.FS

// Dist returns the embedded SPA filesystem rooted at dist/. Stable symbol
// across embed_on / embed_off variants.
func Dist() fs.FS {
	sub, err := fs.Sub(bundle, "dist")
	if err != nil {
		// Constant path — can only fail if dist/ is missing from the
		// embed, which means the binary was built with the embed_web
		// tag before running `make web` (or the equivalent vite build).
		// Surface that as a build-time bug rather than a runtime mystery.
		panic("internal/web: dist subtree missing from embed — did `make web` run before this build? " + err.Error())
	}
	return sub
}

// Embedded reports whether the real web UI is baked into this binary. The
// Handler doesn't check it today, but tests + diagnostics ("doctor")
// can use it to differentiate placeholder-served binaries from real ones.
const Embedded = true
