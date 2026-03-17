package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "0.1.14"

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
	rootCmd.AddCommand(ruleCmd)
	rootCmd.AddCommand(presetCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(tuiCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(healthCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("remote-signer-cli", version)
		return nil
	},
}
