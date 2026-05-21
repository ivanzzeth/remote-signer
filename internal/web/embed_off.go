//go:build !embed_web

// Package web — embed_off variant. Selected by the default `go build`
// (the Makefile's `build` target). Serves a small static placeholder
// page instead of the full Vite-built operator UI.
//
// This exists so backend contributors can `make build` without a Node
// toolchain. Release builds use `make build-embed` which sets the
// `embed_web` build tag and pulls in embed_on.go to bake the real UI.

package web

import (
	"embed"
	"io/fs"
)

//go:embed placeholder
var bundle embed.FS

// Dist returns a filesystem containing only the placeholder index.html.
// Same shape as the embed_on variant — handler.go is unaware which it
// got, and the SPA history-fallback in serveStatic always lands on
// index.html so the placeholder gets rendered for every UI route.
func Dist() fs.FS {
	sub, err := fs.Sub(bundle, "placeholder")
	if err != nil {
		// Constant path — only fails if internal/web/placeholder/ was
		// deleted from source, which would be a bug.
		panic("internal/web: placeholder subtree missing from embed: " + err.Error())
	}
	return sub
}

// Embedded reports whether the real web UI is baked in. Always false in
// this variant; doctor / tests can branch on it.
const Embedded = false
