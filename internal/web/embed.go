// Package web embeds the React single-page application into the daemon
// binary and serves it under the catch-all "/" route.
//
// Vite emits its build artifacts into ./dist next to this file (configured
// via the project root's web/ npm workspace; vite.config.ts sets outDir to
// ../internal/web/dist so the embed directive below sees them). A
// placeholder index.html is committed there so `go build ./...` succeeds
// without first running the npm pipeline; release builds overwrite it
// with the real bundle.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var bundle embed.FS

// Dist returns the embedded filesystem rooted at the Vite output directory
// so callers don't have to know the embed path stem.
func Dist() fs.FS {
	sub, err := fs.Sub(bundle, "dist")
	if err != nil {
		// fs.Sub on a known constant path can only fail if "dist" is
		// missing from the embed.FS — which would mean the binary was
		// built without the placeholder file present, a bug.
		panic("internal/web: dist subtree missing from embed: " + err.Error())
	}
	return sub
}
