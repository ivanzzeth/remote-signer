// Binary remote-signer is the unified entrypoint for the remote-signer
// service and tooling. Subcommands:
//
//	remote-signer server start [-config ...]   start the daemon
//	remote-signer tui [...]                    launch the operator TUI
//	remote-signer validate [...]               validate rule files / config
//	remote-signer rule | sign | keystore | ... operator/admin commands
//	remote-signer version                      print version
//
// Server/TUI/validate keep their original flag-style CLI surface
// (`-config foo.yaml`, `-api-key-id ...`); DisableFlagParsing forwards them
// untouched to the underlying internal/cli/<name>.Run implementation so
// existing scripts that pass `-flag` instead of `--flag` keep working.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/remote-signer/internal/cli/admin"
	"github.com/ivanzzeth/remote-signer/internal/cli/server"
	"github.com/ivanzzeth/remote-signer/internal/cli/tui"
	"github.com/ivanzzeth/remote-signer/internal/cli/validate"
	"github.com/ivanzzeth/remote-signer/internal/version"
)

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "remote-signer",
		Short: "Remote signer service, TUI, validator, and operator CLI in one binary",
		Long: `remote-signer is a single binary that hosts the signing service and every
operator tool that talks to it. Use 'remote-signer server start' to run the
daemon, 'remote-signer tui' to launch the interactive client, and
'remote-signer validate' to check rule files. All other subcommands operate
the service over its HTTP API.`,
		SilenceUsage: true,
	}

	root.AddCommand(newServerCmd())
	root.AddCommand(newTUICmd())
	root.AddCommand(newValidateCmd())
	root.AddCommand(newVersionCmd())

	// Admin operator commands (rule/sign/keystore/preset/apikey/...).
	// Note: admin.Register also installs persistent auth flags
	// (-url/-api-key-id/...) on root.
	admin.Register(root)
	return root
}

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Manage the remote-signer service",
	}
	cmd.AddCommand(&cobra.Command{
		Use:                "start",
		Short:              "Start the remote-signer daemon",
		Long:               "Start the remote-signer HTTP service. Flags are forwarded to the server implementation, e.g. `remote-signer server start -config config.yaml -env .env`.",
		DisableFlagParsing: true,
		SilenceErrors:      true, // server.Run prints its own diagnostics; main.go renders the final error
		RunE: func(_ *cobra.Command, args []string) error {
			return server.Run(args)
		},
	})
	return cmd
}

func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:                "tui",
		Short:              "Launch the interactive TUI client",
		Long:               "Launch the operator TUI. Flags are forwarded to the TUI implementation, e.g. `remote-signer tui -api-key-id admin -api-key-file data/admin_private.pem -url https://localhost:8548`.",
		DisableFlagParsing: true,
		SilenceErrors:      true,
		RunE: func(_ *cobra.Command, args []string) error {
			return tui.Run(args)
		},
	}
}

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "validate",
		Short:              "Validate rule files (offline; same pipeline as the server)",
		Long:               "Validate one or more rule YAML files, or expand and validate a full config. Flags are forwarded to the validator implementation, e.g. `remote-signer validate -config config.yaml`.",
		DisableFlagParsing: true,
		SilenceErrors:      true,
		RunE: func(_ *cobra.Command, args []string) error {
			return validate.Run(args)
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print remote-signer version",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Fprintln(os.Stdout, "remote-signer", version.Version)
			return nil
		},
	}
}
