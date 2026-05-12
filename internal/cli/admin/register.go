// Package admin holds every cobra subcommand that the operator-facing
// `remote-signer` CLI exposes (rule/sign/keystore/preset/apikey/...).
// cmd/remote-signer wires these via Register so they become subcommands of the
// unified `remote-signer` binary; cmd/remote-signer-cli is a thin shim that
// calls Run for backwards compatibility while the standalone binary is being
// retired.
package admin

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/remote-signer/internal/version"
)

// Register wires every admin subcommand onto root and installs the shared
// auth persistent flags (-url/-api-key-id/etc). Call this from a cobra root
// command to expose the operator CLI as `<root> rule ...`, `<root> sign ...`,
// and so on.
func Register(root *cobra.Command) {
	registerAuthFlags(root)

	// Chain-specific: canonical path is "evm rule", "evm sign", etc.
	root.AddCommand(evmCmd)

	// Top-level aliases for backward compatibility (scripts, setup.sh, etc.)
	// "rule ..." is equivalent to "evm rule ..."
	// "sign ..." is equivalent to "evm sign ..."
	root.AddCommand(ruleCmd)
	root.AddCommand(signCmd)

	// Top-level aliases for management commands
	root.AddCommand(apiKeyCmd)
	root.AddCommand(templateCmd)
	root.AddCommand(auditCmd)
	root.AddCommand(aclCmd)

	// Cross-chain / global commands stay at top level
	root.AddCommand(presetCmd)
	root.AddCommand(validateCmd)
	root.AddCommand(tuiCmd)
	root.AddCommand(keystoreCmd)
	root.AddCommand(versionCmd)
	root.AddCommand(healthCmd)
	root.AddCommand(metricsCmd)
	root.AddCommand(doctorCmd)
}

// Run executes the admin CLI standalone (for the deprecated remote-signer-cli
// shim). args should be os.Args[1:].
func Run(args []string) error {
	// Pass-through subcommands: forward all args to the child binary so flags like -config work.
	// Cobra's PrePersistentRun would otherwise complain about unknown flags before reaching
	// these subcommands, so we short-circuit here. Once the v0.3.0 unified binary lands,
	// validate/tui become in-process cobra commands and this pass-through goes away.
	if len(args) >= 1 {
		switch args[0] {
		case "validate":
			return runValidate(args[1:])
		case "tui":
			return runTUI(args[1:])
		}
	}
	root := newRootCmd()
	Register(root)
	root.SetArgs(args)
	return root.Execute()
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remote-signer-cli",
		Short: "CLI for rules, validation, and TUI",
		Long: `remote-signer-cli provides subcommands for rule templates/presets,
rule validation (via remote-signer-validate-rules), and launching the TUI (remote-signer-tui).`,
		SilenceUsage: true,
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(os.Stdout, "remote-signer-cli", version.Version)
		return nil
	},
}
