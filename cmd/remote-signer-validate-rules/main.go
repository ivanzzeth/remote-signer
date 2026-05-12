// Binary remote-signer-validate-rules is a thin entrypoint for the rule
// validator. The implementation lives in internal/cli/validate so it can also
// be wired as a cobra subcommand of the unified `remote-signer` binary.
//
// This standalone binary will be removed once the v0.3.0 unified-binary
// refactor lands; new code should depend on internal/cli/validate directly.
package main

import (
	"fmt"
	"os"

	"github.com/ivanzzeth/remote-signer/internal/cli/validate"
)

func main() {
	if err := validate.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
