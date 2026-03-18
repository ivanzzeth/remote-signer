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

// ── simulate batch ──────────────────────────────────────────────────────────

var (
	simBatchChainID string
	simBatchFrom    string
	simBatchTxs     []string // format: "to:value:data" per tx
)

var simulateBatchCmd = &cobra.Command{
	Use:   "batch --chain-id <id> --from <addr> --tx <to>:<value>:<data> [--tx ...]",
	Short: "Simulate multiple transactions in sequence (batch)",
	Long: `Simulate multiple transactions in a single batch. Each --tx flag is "to:value:data".
Example: simulate batch --chain-id 137 --from 0xABC --tx 0xUSDC:0x0:0x095ea7b3... --tx 0xRouter:0x0:0xf2c42696...`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(simBatchTxs) == 0 {
			return fmt.Errorf("at least one --tx is required")
		}

		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		var txs []evm.SimulateTxDTO
		for _, raw := range simBatchTxs {
			parts := splitBatchTx(raw)
			if len(parts) < 3 {
				return fmt.Errorf("invalid --tx format %q, expected to:value:data", raw)
			}
			txs = append(txs, evm.SimulateTxDTO{
				To:    parts[0],
				Value: parts[1],
				Data:  parts[2],
			})
		}

		resp, err := c.EVM.Simulate.SimulateBatch(context.Background(), &evm.SimulateBatchRequest{
			ChainID:      simBatchChainID,
			From:         simBatchFrom,
			Transactions: txs,
		})
		if err != nil {
			return fmt.Errorf("batch simulation failed: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		for i, r := range resp.Results {
			status := "SUCCESS"
			if !r.Success {
				status = "REVERTED"
			}
			fmt.Printf("Tx %d: %s  gas=%d  approval=%v\n", i, status, r.GasUsed, r.HasApproval)
			if r.RevertReason != "" {
				fmt.Printf("  Revert: %s\n", r.RevertReason)
			}
			for _, bc := range r.BalanceChanges {
				fmt.Printf("  %s %s: %s (%s)\n", bc.Token, bc.Direction, bc.Amount, bc.Standard)
			}
		}

		if len(resp.NetBalanceChanges) > 0 {
			fmt.Println("\nNet Balance Changes:")
			printTable(
				[]string{"TOKEN", "STANDARD", "AMOUNT", "DIRECTION"},
				func() [][]string {
					rows := make([][]string, len(resp.NetBalanceChanges))
					for i, bc := range resp.NetBalanceChanges {
						rows[i] = []string{bc.Token, bc.Standard, bc.Amount, bc.Direction}
					}
					return rows
				}(),
			)
		}

		return nil
	},
}

// splitBatchTx splits "to:value:data" — data may contain colons (hex), so split on first 2 only.
func splitBatchTx(s string) []string {
	// Split into at most 3 parts: to, value, data (data can contain ':')
	parts := make([]string, 0, 3)
	for i := 0; i < 2; i++ {
		idx := 0
		for idx < len(s) && s[idx] != ':' {
			idx++
		}
		if idx >= len(s) {
			break
		}
		parts = append(parts, s[:idx])
		s = s[idx+1:]
	}
	parts = append(parts, s)
	return parts
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

	simulateBatchCmd.Flags().StringVar(&simBatchChainID, "chain-id", "1", "Chain ID")
	simulateBatchCmd.Flags().StringVar(&simBatchFrom, "from", "", "Sender address")
	simulateBatchCmd.Flags().StringArrayVar(&simBatchTxs, "tx", nil, "Transaction in format to:value:data (repeatable)")
	if err := simulateBatchCmd.MarkFlagRequired("from"); err != nil {
		panic(err)
	}

	simulateCmd.AddCommand(simulateTxCmd)
	simulateCmd.AddCommand(simulateBatchCmd)
	simulateCmd.AddCommand(simulateStatusCmd)
}

