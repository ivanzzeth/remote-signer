package main

import (
	"fmt"
	"strconv"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/spf13/cobra"
)

var signerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Manage EVM signers (list, unlock, lock)",
}

// ── signer list ──────────────────────────────────────────────────────────────

var signerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available signers",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.EVM.Signers.List(cmd.Context(), nil)
		if err != nil {
			return fmt.Errorf("list signers: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(resp)
		}
		fmt.Printf("Total: %d\n", resp.Total)
		printTable(
			[]string{"ADDRESS", "TYPE", "ENABLED", "LOCKED"},
			func() [][]string {
				rows := make([][]string, len(resp.Signers))
				for i, s := range resp.Signers {
					rows[i] = []string{s.Address, s.Type, strconv.FormatBool(s.Enabled), strconv.FormatBool(s.Locked)}
				}
				return rows
			}(),
		)
		return nil
	},
}

// ── signer create ────────────────────────────────────────────────────────────

var signerCreatePassword string

var signerCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new keystore signer (admin only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		signer, err := c.EVM.Signers.Create(cmd.Context(), &evm.CreateSignerRequest{
			Type: "keystore",
			Keystore: &evm.CreateKeystoreParams{
				Password: signerCreatePassword,
			},
		})
		if err != nil {
			return fmt.Errorf("create signer: %w", err)
		}
		fmt.Printf("Created signer: %s\n", signer.Address)
		return printJSON(signer)
	},
}

// ── signer unlock ────────────────────────────────────────────────────────────

var signerUnlockPassword string

var signerUnlockCmd = &cobra.Command{
	Use:   "unlock <address>",
	Short: "Unlock a signer with its password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.EVM.Signers.Unlock(cmd.Context(), args[0], &evm.UnlockSignerRequest{
			Password: signerUnlockPassword,
		})
		if err != nil {
			return fmt.Errorf("unlock signer: %w", err)
		}
		fmt.Printf("Signer %s unlocked\n", resp.Address)
		return nil
	},
}

// ── signer lock ──────────────────────────────────────────────────────────────

var signerLockCmd = &cobra.Command{
	Use:   "lock <address>",
	Short: "Lock a signer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.EVM.Signers.Lock(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("lock signer: %w", err)
		}
		fmt.Printf("Signer %s locked\n", resp.Address)
		return nil
	},
}

func init() {
	signerUnlockCmd.Flags().StringVar(&signerUnlockPassword, "password", "", "Keystore password")
	if err := signerUnlockCmd.MarkFlagRequired("password"); err != nil {
		panic(err)
	}

	signerCreateCmd.Flags().StringVar(&signerCreatePassword, "password", "", "Keystore password")
	if err := signerCreateCmd.MarkFlagRequired("password"); err != nil {
		panic(err)
	}

	signerCmd.AddCommand(signerListCmd)
	signerCmd.AddCommand(signerCreateCmd)
	signerCmd.AddCommand(signerUnlockCmd)
	signerCmd.AddCommand(signerLockCmd)
}
