package main

import (
	"fmt"
	"strconv"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/spf13/cobra"
)

var signerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Manage EVM signers (list, create, unlock, lock, approve, transfer, delete, access)",
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
			[]string{"ADDRESS", "TYPE", "ENABLED", "LOCKED", "OWNER", "STATUS"},
			func() [][]string {
				rows := make([][]string, len(resp.Signers))
				for i, s := range resp.Signers {
					rows[i] = []string{s.Address, s.Type, strconv.FormatBool(s.Enabled), strconv.FormatBool(s.Locked), s.OwnerID, s.Status}
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
	Short: "Create a new keystore signer",
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

// ── signer approve ───────────────────────────────────────────────────────────

var signerApproveCmd = &cobra.Command{
	Use:   "approve <address>",
	Short: "Approve a pending signer (admin only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Signers.ApproveSigner(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("approve signer: %w", err)
		}
		fmt.Printf("Signer %s approved\n", args[0])
		return nil
	},
}

// ── signer access ────────────────────────────────────────────────────────────

// ── signer transfer ───────────────────────────────────────────────────────

var signerTransferTo string

var signerTransferCmd = &cobra.Command{
	Use:   "transfer <address>",
	Short: "Transfer signer ownership to another API key (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Signers.TransferOwnership(cmd.Context(), args[0], &evm.TransferOwnershipRequest{
			NewOwnerID: signerTransferTo,
		}); err != nil {
			return fmt.Errorf("transfer signer: %w", err)
		}
		fmt.Printf("Signer %s transferred to %s\n", args[0], signerTransferTo)
		return nil
	},
}

// ── signer delete ─────────────────────────────────────────────────────────

var signerDeleteCmd = &cobra.Command{
	Use:   "delete <address>",
	Short: "Delete a signer (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Signers.DeleteSigner(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("delete signer: %w", err)
		}
		fmt.Printf("Signer %s deleted\n", args[0])
		return nil
	},
}

// ── signer access ────────────────────────────────────────────────────────

var signerAccessCmd = &cobra.Command{
	Use:   "access",
	Short: "Manage signer access grants",
}

var signerAccessGrantKeyID string

var signerAccessGrantCmd = &cobra.Command{
	Use:   "grant <address>",
	Short: "Grant access to a signer for another API key (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Signers.GrantAccess(cmd.Context(), args[0], &evm.GrantAccessRequest{
			APIKeyID: signerAccessGrantKeyID,
		}); err != nil {
			return fmt.Errorf("grant access: %w", err)
		}
		fmt.Printf("Access granted to %s for signer %s\n", signerAccessGrantKeyID, args[0])
		return nil
	},
}

var signerAccessRevokeKeyID string

var signerAccessRevokeCmd = &cobra.Command{
	Use:   "revoke <address>",
	Short: "Revoke access from a signer for an API key (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Signers.RevokeAccess(cmd.Context(), args[0], signerAccessRevokeKeyID); err != nil {
			return fmt.Errorf("revoke access: %w", err)
		}
		fmt.Printf("Access revoked from %s for signer %s\n", signerAccessRevokeKeyID, args[0])
		return nil
	},
}

var signerAccessListCmd = &cobra.Command{
	Use:   "list <address>",
	Short: "List access grants for a signer (owner only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		accesses, err := c.EVM.Signers.ListAccess(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("list access: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(accesses)
		}
		printTable(
			[]string{"API_KEY_ID", "GRANTED_BY", "CREATED_AT"},
			func() [][]string {
				rows := make([][]string, len(accesses))
				for i, a := range accesses {
					rows[i] = []string{a.APIKeyID, a.GrantedBy, a.CreatedAt.Format("2006-01-02T15:04:05Z")}
				}
				return rows
			}(),
		)
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

	signerAccessGrantCmd.Flags().StringVar(&signerAccessGrantKeyID, "to", "", "API key ID to grant access to")
	if err := signerAccessGrantCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}

	signerAccessRevokeCmd.Flags().StringVar(&signerAccessRevokeKeyID, "from", "", "API key ID to revoke access from")
	if err := signerAccessRevokeCmd.MarkFlagRequired("from"); err != nil {
		panic(err)
	}

	signerTransferCmd.Flags().StringVar(&signerTransferTo, "to", "", "API key ID to transfer ownership to")
	if err := signerTransferCmd.MarkFlagRequired("to"); err != nil {
		panic(err)
	}

	signerAccessCmd.AddCommand(signerAccessGrantCmd)
	signerAccessCmd.AddCommand(signerAccessRevokeCmd)
	signerAccessCmd.AddCommand(signerAccessListCmd)

	signerCmd.AddCommand(signerListCmd)
	signerCmd.AddCommand(signerCreateCmd)
	signerCmd.AddCommand(signerUnlockCmd)
	signerCmd.AddCommand(signerLockCmd)
	signerCmd.AddCommand(signerApproveCmd)
	signerCmd.AddCommand(signerTransferCmd)
	signerCmd.AddCommand(signerDeleteCmd)
	signerCmd.AddCommand(signerAccessCmd)
}
