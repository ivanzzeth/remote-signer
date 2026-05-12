// Binary remote-signer is a thin entrypoint for the daemon. The implementation
// lives in internal/cli/server so it can also be wired as a cobra subcommand
// of the unified `remote-signer` binary.
//
// PR1 of the v0.3.0 unified-binary refactor only extracts the implementation;
// PR2 will replace this file with a cobra root command that exposes
// `server start`, `tui`, `validate`, and admin subcommands.
package main

import (
	"fmt"
	"os"

	"github.com/ivanzzeth/remote-signer/internal/cli/server"
)

func main() {
	if err := server.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
