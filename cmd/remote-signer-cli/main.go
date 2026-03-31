package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "0.1.15"

func main() {
	// Pass-through subcommands: forward all args to the child binary so flags like -config work.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "validate":
			if err := runValidate(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		case "tui":
			if err := runTUI(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "remote-signer-cli",
	Short: "CLI for rules, validation, and TUI",
	Long: `remote-signer-cli provides subcommands for rule templates/presets,
rule validation (via remote-signer-validate-rules), and launching the TUI (remote-signer-tui).`,
	SilenceUsage: true,
}

func init() {
	registerAuthFlags(rootCmd)

	// Chain-specific: canonical path is "evm rule", "evm sign", etc.
	rootCmd.AddCommand(evmCmd)

	// Top-level aliases for backward compatibility (scripts, setup.sh, etc.)
	// "rule ..." is equivalent to "evm rule ..."
	// "sign ..." is equivalent to "evm sign ..."
	rootCmd.AddCommand(ruleCmd)
	rootCmd.AddCommand(signCmd)

	// Cross-chain / global commands stay at top level
	rootCmd.AddCommand(presetCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(tuiCmd)
	rootCmd.AddCommand(keystoreCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(metricsCmd)
	rootCmd.AddCommand(doctorCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("remote-signer-cli", version)
		return nil
	},
}
