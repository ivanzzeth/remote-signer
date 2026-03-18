package main

import (
	"context"
	"fmt"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/spf13/cobra"
)

var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Simulate EVM transactions and check simulation status",
}

// ── simulate tx ─────────────────────────────────────────────────────────────

var (
	simChainID string
	simFrom    string
	simTo      string
	simValue   string
	simData    string
	simGas     string
)

var simulateTxCmd = &cobra.Command{
	Use:   "tx",
	Short: "Simulate a single EVM transaction",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		req := &evm.SimulateRequest{
			ChainID: simChainID,
			From:    simFrom,
			To:      simTo,
			Value:   simValue,
			Data:    simData,
			Gas:     simGas,
		}

		resp, err := c.EVM.Simulate.Simulate(context.Background(), req)
		if err != nil {
			return fmt.Errorf("simulation failed: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		// Formatted output
		status := "SUCCESS"
		if !resp.Success {
			status = "REVERTED"
		}
		fmt.Printf("Status:       %s\n", status)
		fmt.Printf("Gas Used:     %d\n", resp.GasUsed)
		fmt.Printf("Has Approval: %v\n", resp.HasApproval)
		if resp.RevertReason != "" {
			fmt.Printf("Revert:       %s\n", resp.RevertReason)
		}

		if len(resp.BalanceChanges) > 0 {
			fmt.Println("\nBalance Changes:")
			printTable(
				[]string{"TOKEN", "STANDARD", "AMOUNT", "DIRECTION"},
				func() [][]string {
					rows := make([][]string, len(resp.BalanceChanges))
					for i, bc := range resp.BalanceChanges {
						rows[i] = []string{bc.Token, bc.Standard, bc.Amount, bc.Direction}
					}
					return rows
				}(),
			)
		}

		if len(resp.Events) > 0 {
			fmt.Println("\nEvents:")
			printTable(
				[]string{"ADDRESS", "EVENT", "STANDARD"},
				func() [][]string {
					rows := make([][]string, len(resp.Events))
					for i, ev := range resp.Events {
						rows[i] = []string{ev.Address, ev.Event, ev.Standard}
					}
					return rows
				}(),
			)
		}

		return nil
	},
}

// ── simulate status ─────────────────────────────────────────────────────────

var simulateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show simulation engine status (anvil fork instances)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		resp, err := c.EVM.Simulate.Status(context.Background())
		if err != nil {
			return fmt.Errorf("status check failed: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		fmt.Printf("Enabled:       %v\n", resp.Enabled)
		fmt.Printf("Anvil Version: %s\n", resp.AnvilVersion)

		if len(resp.Chains) == 0 {
			fmt.Println("Chains:        (none running)")
			return nil
		}

		fmt.Println("\nChains:")
		headers := []string{"CHAIN_ID", "STATUS", "PORT", "BLOCK", "RESTARTS", "DIRTY", "ERROR"}
		var rows [][]string
		for chainID, cs := range resp.Chains {
			rows = append(rows, []string{
				chainID,
				cs.Status,
				fmt.Sprintf("%d", cs.Port),
				cs.BlockNumber,
				fmt.Sprintf("%d", cs.RestartCount),
				fmt.Sprintf("%v", cs.Dirty),
				cs.Error,
			})
		}
		printTable(headers, rows)

		return nil
	},
}

func init() {
	simulateTxCmd.Flags().StringVar(&simChainID, "chain-id", "1", "Chain ID")
	simulateTxCmd.Flags().StringVar(&simFrom, "from", "", "Sender address (0x-prefixed)")
	simulateTxCmd.Flags().StringVar(&simTo, "to", "", "Recipient address (0x-prefixed)")
	simulateTxCmd.Flags().StringVar(&simValue, "value", "0x0", "Value in hex wei")
	simulateTxCmd.Flags().StringVar(&simData, "data", "", "Calldata (0x hex)")
	simulateTxCmd.Flags().StringVar(&simGas, "gas", "", "Gas limit (hex)")

	if err := simulateTxCmd.MarkFlagRequired("from"); err != nil {
		panic(err)
	}
	if err := simulateTxCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}

	simulateCmd.AddCommand(simulateTxCmd)
	simulateCmd.AddCommand(simulateStatusCmd)
}

