package main

import "github.com/spf13/cobra"

// evmCmd is the parent for all EVM-specific commands.
var evmCmd = &cobra.Command{
	Use:   "evm",
	Short: "EVM chain operations (sign, rule, signer, request)",
}

func init() {
	evmCmd.AddCommand(signCmd)
	evmCmd.AddCommand(ruleCmd)
	evmCmd.AddCommand(signerCmd)
	evmCmd.AddCommand(simulateCmd)
}
