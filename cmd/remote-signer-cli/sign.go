package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign transactions, messages, and typed data via remote-signer",
}

// ── sign tx ──────────────────────────────────────────────────────────────────

var signTxCmd = &cobra.Command{
	Use:   "tx",
	Short: "Sign an EVM transaction",
	Long: `Sign an EVM transaction (Legacy, EIP-2930, or EIP-1559).

Returns the signed raw transaction hex and signature. If the request requires
manual approval, returns a pending status with a request_id.

Example (EIP-1559):
  remote-signer-cli evm sign tx \
    --signer 0xYourAddress \
    --chain-id 1 \
    --to 0xRecipient \
    --value 0 \
    --data 0x \
    --gas 21000 \
    --tx-type eip1559 \
    --gas-tip-cap 1000000000 \
    --gas-fee-cap 30000000000 \
    --nonce -1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		tx := &evm.Transaction{
			Value:  signTxValue,
			Gas:    signTxGas,
			TxType: signTxType,
		}
		if signTxTo != "" {
			tx.To = &signTxTo
		}
		if signTxData != "" {
			tx.Data = signTxData
		}
		if signTxNonce >= 0 {
			n := uint64(signTxNonce)
			tx.Nonce = &n
		}
		if signTxGasPrice != "" {
			tx.GasPrice = signTxGasPrice
		}
		if signTxGasTipCap != "" {
			tx.GasTipCap = signTxGasTipCap
		}
		if signTxGasFeeCap != "" {
			tx.GasFeeCap = signTxGasFeeCap
		}

		payload, err := json.Marshal(&evm.TransactionPayload{Transaction: tx})
		if err != nil {
			return fmt.Errorf("failed to marshal transaction: %w", err)
		}

		req := &evm.SignRequest{
			ChainID:       signChainID,
			SignerAddress: signSignerAddress,
			SignType:      evm.SignTypeTransaction,
			Payload:       payload,
		}

		resp, err := c.EVM.Sign.Execute(context.Background(), req)
		if err != nil {
			return fmt.Errorf("sign failed: %w", err)
		}
		return outputSignResponse(resp)
	},
}

// ── sign personal ────────────────────────────────────────────────────────────

var signPersonalCmd = &cobra.Command{
	Use:   "personal <message>",
	Short: "Sign a personal message (EIP-191 personal_sign)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		payload, err := json.Marshal(&evm.MessagePayload{Message: args[0]})
		if err != nil {
			return fmt.Errorf("failed to marshal message: %w", err)
		}

		signType := evm.SignTypePersonal
		if signPersonalEIP191 {
			signType = evm.SignTypeEIP191
		}

		req := &evm.SignRequest{
			ChainID:       signChainID,
			SignerAddress: signSignerAddress,
			SignType:      signType,
			Payload:       payload,
		}

		resp, err := c.EVM.Sign.Execute(context.Background(), req)
		if err != nil {
			return fmt.Errorf("sign failed: %w", err)
		}
		return outputSignResponse(resp)
	},
}

// ── sign hash ────────────────────────────────────────────────────────────────

var signHashCmd = &cobra.Command{
	Use:   "hash <0x-prefixed-hash>",
	Short: "Sign a 32-byte hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		hash := args[0]
		if !strings.HasPrefix(hash, "0x") {
			hash = "0x" + hash
		}

		payload, err := json.Marshal(&evm.HashPayload{Hash: hash})
		if err != nil {
			return fmt.Errorf("failed to marshal hash: %w", err)
		}

		req := &evm.SignRequest{
			ChainID:       signChainID,
			SignerAddress: signSignerAddress,
			SignType:      evm.SignTypeHash,
			Payload:       payload,
		}

		resp, err := c.EVM.Sign.Execute(context.Background(), req)
		if err != nil {
			return fmt.Errorf("sign failed: %w", err)
		}
		return outputSignResponse(resp)
	},
}

// ── sign typed-data ──────────────────────────────────────────────────────────

var signTypedDataCmd = &cobra.Command{
	Use:   "typed-data <json-file-or-stdin>",
	Short: "Sign EIP-712 typed data from a JSON file (use - for stdin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		var data []byte
		if args[0] == "-" {
			data, err = os.ReadFile("/dev/stdin")
		} else {
			data, err = os.ReadFile(args[0]) // #nosec G304 -- user-provided path
		}
		if err != nil {
			return fmt.Errorf("failed to read typed data: %w", err)
		}

		var td evm.TypedData
		if err := json.Unmarshal(data, &td); err != nil {
			return fmt.Errorf("failed to parse typed data JSON: %w", err)
		}

		payload, err := json.Marshal(&evm.TypedDataPayload{TypedData: &td})
		if err != nil {
			return fmt.Errorf("failed to marshal typed data: %w", err)
		}

		req := &evm.SignRequest{
			ChainID:       signChainID,
			SignerAddress: signSignerAddress,
			SignType:      evm.SignTypeTypedData,
			Payload:       payload,
		}

		resp, err := c.EVM.Sign.Execute(context.Background(), req)
		if err != nil {
			return fmt.Errorf("sign failed: %w", err)
		}
		return outputSignResponse(resp)
	},
}

// ── flags ────────────────────────────────────────────────────────────────────

var (
	signChainID       string
	signSignerAddress string

	// tx flags
	signTxTo        string
	signTxValue     string
	signTxData      string
	signTxNonce     int64
	signTxGas       uint64
	signTxGasPrice  string
	signTxGasTipCap string
	signTxGasFeeCap string
	signTxType      string

	// personal flags
	signPersonalEIP191 bool
)

func init() {
	// Common flags on parent
	signCmd.PersistentFlags().StringVar(&signChainID, "chain-id", "1", "Chain ID")
	signCmd.PersistentFlags().StringVar(&signSignerAddress, "signer", "", "Signer address (0x-prefixed)")
	if err := signCmd.MarkPersistentFlagRequired("signer"); err != nil {
		panic(err)
	}

	// tx subcommand
	signTxCmd.Flags().StringVar(&signTxTo, "to", "", "Recipient address")
	signTxCmd.Flags().StringVar(&signTxValue, "value", "0", "Value in wei")
	signTxCmd.Flags().StringVar(&signTxData, "data", "", "Calldata (0x hex)")
	signTxCmd.Flags().Int64Var(&signTxNonce, "nonce", -1, "Nonce (-1 = auto-fetch from chain)")
	signTxCmd.Flags().Uint64Var(&signTxGas, "gas", 21000, "Gas limit")
	signTxCmd.Flags().StringVar(&signTxGasPrice, "gas-price", "", "Gas price in wei (legacy)")
	signTxCmd.Flags().StringVar(&signTxGasTipCap, "gas-tip-cap", "", "Max priority fee per gas in wei, decimal (e.g. 30000000000 for 30 Gwei)")
	signTxCmd.Flags().StringVar(&signTxGasFeeCap, "gas-fee-cap", "", "Max fee per gas in wei, decimal (e.g. 30000000000 for 30 Gwei)")
	signTxCmd.Flags().StringVar(&signTxType, "tx-type", "legacy", "Transaction type: legacy, eip1559, eip2930")

	// personal subcommand
	signPersonalCmd.Flags().BoolVar(&signPersonalEIP191, "eip191", false, "Use EIP-191 instead of personal_sign")

	signCmd.AddCommand(signTxCmd)
	signCmd.AddCommand(signPersonalCmd)
	signCmd.AddCommand(signHashCmd)
	signCmd.AddCommand(signTypedDataCmd)
}

func outputSignResponse(resp *evm.SignResponse) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}
