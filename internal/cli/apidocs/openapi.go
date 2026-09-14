// Package apidocs implements the `remote-signer openapi` CLI command.
//
// ⛔ Its whole job is to write out the document that was generated at build
// time. It does **not** build a router, and that is the point (proposal §4.1):
// a spec produced by walking a live *api.Router would describe one wiring —
// NewRouter needs five dependencies and a database, and setupRoutes registers
// conditionally — rather than the API this code serves. Printing an embedded
// file means the command needs no database, no socket, no config and no Go
// toolchain, so it works inside the shipped container.
package apidocs

import (
	"fmt"
	"io"

	"github.com/ivanzzeth/remote-signer/internal/apidocs"
)

// Run writes the embedded OpenAPI document to w.
//
// It takes no arguments on purpose: an `-o file` flag would be a second way to
// do `> file`, and a `--format yaml` flag would mean this command converting a
// document it did not generate.
func Run(w io.Writer, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("openapi takes no arguments (got %q); redirect stdout to write a file: remote-signer openapi > openapi.json", args[0])
	}
	if len(apidocs.Spec) == 0 {
		// Unreachable through `make build`: //go:embed fails at compile time on
		// a missing file. Reachable if someone commits an empty one.
		return fmt.Errorf("the embedded OpenAPI document is empty — regenerate it with `make openapi`")
	}
	if _, err := w.Write(apidocs.Spec); err != nil {
		return fmt.Errorf("write spec: %w", err)
	}
	return nil
}
