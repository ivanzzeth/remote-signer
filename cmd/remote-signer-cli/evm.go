package main

import "github.com/spf13/cobra"

// evmCmd is the parent for all EVM-specific commands.
var evmCmd = &cobra.Command{
	Use:     "evm",
	Aliases: []string{"chain"},
	Short:   "EVM chain operations (sign, rule, signer, request); alias: chain",
}

func init() {
	evmCmd.AddCommand(signCmd)
	evmCmd.AddCommand(ruleCmd)
	evmCmd.AddCommand(signerCmd)
	evmCmd.AddCommand(simulateCmd)
	evmCmd.AddCommand(requestCmd)
	evmCmd.AddCommand(guardCmd)
	evmCmd.AddCommand(broadcastCmd)
	evmCmd.AddCommand(hdwalletCmd)
	evmCmd.AddCommand(apiKeyCmd)
	evmCmd.AddCommand(templateCmd)
}
