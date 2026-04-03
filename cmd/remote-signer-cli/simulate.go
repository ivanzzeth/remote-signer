package main

import (
	"context"
	"encoding/json"
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
	Short: "Show simulation engine status (eth_simulateV1 via RPC gateway)",
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
		fmt.Printf("Engine: %s\n", resp.EngineVersion)

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
	simBatchTxs     []string // format: JSON per tx
)

var simulateBatchCmd = &cobra.Command{
	Use:   `batch --chain-id <id> --from <addr> --tx '{"to":"0x...","value":"0x0","data":"0x..."}' [--tx ...]`,
	Short: "Simulate multiple transactions in sequence (batch)",
	Long: `Simulate multiple transactions in a single batch. Each --tx flag is a JSON object.

Example:
  simulate batch --chain-id 137 --from 0xABC \
    --tx '{"to":"0xUSDC","value":"0x0","data":"0x095ea7b3..."}' \
    --tx '{"to":"0xRouter","value":"0x0","data":"0xf2c42696..."}'`,
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
			var tx evm.SimulateTxDTO
			if err := json.Unmarshal([]byte(raw), &tx); err != nil {
				return fmt.Errorf("invalid --tx JSON %q: %w", raw, err)
			}
			txs = append(txs, tx)
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

func init() {
	simulateTxCmd.Flags().StringVar(&simChainID, "chain-id", "1", "Chain ID")
	simulateTxCmd.Flags().StringVar(&simFrom, "from", "", "Sender address (0x-prefixed, 42 chars)")
	simulateTxCmd.Flags().StringVar(&simTo, "to", "", "Recipient address (0x-prefixed, 42 chars)")
	simulateTxCmd.Flags().StringVar(&simValue, "value", "0x0", "Value in wei (decimal or hex, e.g. '1000000' or '0xF4240')")
	simulateTxCmd.Flags().StringVar(&simData, "data", "", "Calldata (0x-prefixed hex)")
	simulateTxCmd.Flags().StringVar(&simGas, "gas", "", "Gas limit (decimal or hex)")

	if err := simulateTxCmd.MarkFlagRequired("from"); err != nil {
		panic(err)
	}
	if err := simulateTxCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}

	simulateBatchCmd.Flags().StringVar(&simBatchChainID, "chain-id", "1", "Chain ID")
	simulateBatchCmd.Flags().StringVar(&simBatchFrom, "from", "", "Sender address")
	simulateBatchCmd.Flags().StringArrayVar(&simBatchTxs, "tx", nil, `Transaction as JSON: '{"to":"0x...","value":"0x0","data":"0x..."}' (repeatable)`)
	if err := simulateBatchCmd.MarkFlagRequired("from"); err != nil {
		panic(err)
	}

	simulateCmd.AddCommand(simulateTxCmd)
	simulateCmd.AddCommand(simulateBatchCmd)
	simulateCmd.AddCommand(simulateStatusCmd)
}

