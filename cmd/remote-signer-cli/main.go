// Binary remote-signer-cli is a thin entrypoint for the admin/operator CLI.
// The implementation lives in internal/cli/admin so it can also be wired as
// part of the unified `remote-signer` binary.
//
// This standalone binary will be removed once the v0.3.0 unified-binary
// refactor lands; new code should depend on internal/cli/admin directly.
package main

import (
	"fmt"
	"os"

	"github.com/ivanzzeth/remote-signer/internal/cli/admin"
)

func main() {
	if err := admin.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
