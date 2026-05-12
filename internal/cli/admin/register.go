// Package admin holds every operator-facing cobra subcommand that the
// `remote-signer` CLI exposes (rule/sign/keystore/preset/apikey/...).
// cmd/remote-signer wires these via Register so they become subcommands of
// the unified `remote-signer` binary.
//
// `server`, `tui`, `validate`, and `version` are deliberately *not* registered
// here — they live in internal/cli/{server,tui,validate} and are wired
// alongside this package by cmd/remote-signer's root command.
package admin

import (
	"github.com/spf13/cobra"
)

// Register wires every admin subcommand onto root and installs the shared
// auth persistent flags (-url/-api-key-id/etc).
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
	root.AddCommand(keystoreCmd)
	root.AddCommand(healthCmd)
	root.AddCommand(metricsCmd)
	root.AddCommand(doctorCmd)
}
