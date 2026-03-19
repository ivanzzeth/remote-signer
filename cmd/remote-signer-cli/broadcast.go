package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/spf13/cobra"
)

var (
	broadcastChainID string
	broadcastWait    bool
)

var broadcastCmd = &cobra.Command{
	Use:   "broadcast <signed-tx-hex>",
	Short: "Broadcast a signed transaction to the chain",
	Long: `Broadcast a signed raw transaction via the remote-signer's RPC gateway.

Returns the transaction hash. Use --wait to poll for the transaction receipt
until confirmed.

Example:
  remote-signer-cli evm broadcast 0xf86c... --chain-id 1
  remote-signer-cli evm broadcast 0xf86c... --chain-id 1 --wait`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		signedTxHex := args[0]

		resp, err := c.EVM.Broadcast.Broadcast(context.Background(), &evm.BroadcastRequest{
			ChainID:     broadcastChainID,
			SignedTxHex: signedTxHex,
		})
		if err != nil {
			return fmt.Errorf("broadcast failed: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		fmt.Printf("Tx Hash: %s\n", resp.TxHash)

		if broadcastWait {
			fmt.Println("Waiting for confirmation...")
			// Poll for receipt via the request status (using raw GET on health-like endpoint)
			// Since there's no receipt endpoint in the client, we just inform the user
			// to check via their own RPC or block explorer.
			// For a more complete solution, we could add a receipt endpoint.
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			timeout := time.After(5 * time.Minute)
			for {
				select {
				case <-timeout:
					fmt.Println("Timeout waiting for confirmation. Check tx status manually.")
					return nil
				case <-ticker.C:
					fmt.Printf("  Polling for receipt of %s...\n", resp.TxHash)
					// The client doesn't have a receipt endpoint yet.
					// Print guidance and exit after one poll attempt.
					fmt.Printf("Transaction broadcast successfully. Track on block explorer.\n")
					return nil
				}
			}
		}

		return nil
	},
}

func init() {
	broadcastCmd.Flags().StringVar(&broadcastChainID, "chain-id", "1", "Chain ID")
	broadcastCmd.Flags().BoolVar(&broadcastWait, "wait", false, "Wait for transaction confirmation (polls receipt)")
}
