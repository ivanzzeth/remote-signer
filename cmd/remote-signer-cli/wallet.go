package main

import (
	"fmt"
	"strconv"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/spf13/cobra"
)

var walletCmd = &cobra.Command{
	Use:     "wallet",
	Aliases: []string{"wallets"},
	Short:   "Wallet management",
}

var (
	flagWalletName        string
	flagWalletDescription string
	flagWalletOffset      int
	flagWalletLimit       int
	flagMemberSignerAddr  string
)

var walletCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new wallet",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if flagWalletName == "" {
			return fmt.Errorf("--name is required")
		}
		w, err := c.EVM.Wallets.Create(cmd.Context(), &evm.CreateWalletRequest{Name: flagWalletName, Description: flagWalletDescription})
		if err != nil {
			return fmt.Errorf("create wallet: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(w)
		}
		fmt.Printf("Created wallet %s (%s)\n", w.Name, w.ID)
		return nil
	},
}

var walletListCmd = &cobra.Command{
	Use:   "list",
	Short: "List wallets",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.EVM.Wallets.List(cmd.Context(), &evm.ListWalletsFilter{Offset: flagWalletOffset, Limit: flagWalletLimit})
		if err != nil {
			return fmt.Errorf("list wallets: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(resp)
		}
		fmt.Printf("Total: %d\n", resp.Total)
		printTable([]string{"ID", "NAME", "MEMBERS", "CREATED"}, func() [][]string {
			rows := make([][]string, len(resp.Wallets))
			for i, w := range resp.Wallets {
				rows[i] = []string{w.ID, w.Name, strconv.Itoa(w.MemberCount), w.CreatedAt.Format("2006-01-02 15:04")}
			}
			return rows
		}())
		return nil
	},
}

var walletGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get wallet by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		w, err := c.EVM.Wallets.Get(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("get wallet: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(w)
		}
		fmt.Printf("ID: %s\nName: %s\nDescription: %s\nMembers: %d\n", w.ID, w.Name, w.Description, w.MemberCount)
		return nil
	},
}

var walletDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete wallet",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Wallets.Delete(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("delete wallet: %w", err)
		}
		fmt.Printf("Deleted wallet %s\n", args[0])
		return nil
	},
}

var walletMembersCmd = &cobra.Command{Use: "members", Short: "Manage wallet members"}

var walletMembersListCmd = &cobra.Command{
	Use:   "list <walletID>",
	Short: "List wallet members",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.EVM.Wallets.ListMembers(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("list members: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(resp)
		}
		printTable([]string{"WALLET_ID", "SIGNER_ADDRESS", "ADDED_AT"}, func() [][]string {
			rows := make([][]string, len(resp.Members))
			for i, m := range resp.Members {
				rows[i] = []string{m.WalletID, m.SignerAddress, m.AddedAt.Format("2006-01-02 15:04")}
			}
			return rows
		}())
		return nil
	},
}

var walletMembersAddCmd = &cobra.Command{
	Use:   "add <walletID>",
	Short: "Add signer to wallet",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if flagMemberSignerAddr == "" {
			return fmt.Errorf("--signer-address is required")
		}
		member, err := c.EVM.Wallets.AddMember(cmd.Context(), args[0], &evm.AddWalletMemberRequest{SignerAddress: flagMemberSignerAddr})
		if err != nil {
			return fmt.Errorf("add member: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(member)
		}
		fmt.Printf("Added signer %s to wallet %s\n", member.SignerAddress, args[0])
		return nil
	},
}

var walletMembersRemoveCmd = &cobra.Command{
	Use:   "remove <walletID> <signerAddress>",
	Short: "Remove signer from wallet",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Wallets.RemoveMember(cmd.Context(), args[0], args[1]); err != nil {
			return fmt.Errorf("remove member: %w", err)
		}
		fmt.Printf("Removed signer %s from wallet %s\n", args[1], args[0])
		return nil
	},
}

func init() {
	walletCreateCmd.Flags().StringVar(&flagWalletName, "name", "", "Wallet display name")
	walletCreateCmd.Flags().StringVar(&flagWalletDescription, "description", "", "Optional description")
	if err := walletCreateCmd.MarkFlagRequired("name"); err != nil {
		panic(err)
	}
	walletListCmd.Flags().IntVar(&flagWalletOffset, "offset", 0, "Pagination offset")
	walletListCmd.Flags().IntVar(&flagWalletLimit, "limit", 0, "Page size (0 = server default)")
	walletMembersAddCmd.Flags().StringVar(&flagMemberSignerAddr, "signer-address", "", "Signer address to add")

	walletCmd.AddCommand(walletCreateCmd)
	walletCmd.AddCommand(walletListCmd)
	walletCmd.AddCommand(walletGetCmd)
	walletCmd.AddCommand(walletDeleteCmd)
	walletMembersCmd.AddCommand(walletMembersListCmd)
	walletMembersCmd.AddCommand(walletMembersAddCmd)
	walletMembersCmd.AddCommand(walletMembersRemoveCmd)
	walletCmd.AddCommand(walletMembersCmd)

	evmCmd.AddCommand(walletCmd)
}
