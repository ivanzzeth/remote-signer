package main

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// --- hdwallet parent ---

var hdwalletCmd = &cobra.Command{
	Use:     "hdwallet",
	Aliases: []string{"hd-wallet"},
	Short:   "HD wallet management",
}

// --- hdwallet list ---

var hdwalletListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all HD wallets",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.EVM.HDWallets.List(cmd.Context())
		if err != nil {
			return fmt.Errorf("list hd wallets: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		printTable(
			[]string{"PRIMARY_ADDRESS", "BASE_PATH", "DERIVED_COUNT", "LOCKED", "DISPLAY_NAME"},
			func() [][]string {
				rows := make([][]string, len(resp.Wallets))
				for i, w := range resp.Wallets {
					rows[i] = []string{
						w.PrimaryAddress, w.BasePath,
						strconv.Itoa(w.DerivedCount),
						strconv.FormatBool(w.Locked),
						w.DisplayName,
					}
				}
				return rows
			}(),
		)
		return nil
	},
}

// --- hdwallet create ---

var hdwalletCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new HD wallet",
	RunE:  runHDWalletCreate,
}

var (
	flagHDWalletPassword    string
	flagHDWalletEntropyBits int
)

func runHDWalletCreate(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	req := &evm.CreateHDWalletRequest{
		Password:    flagHDWalletPassword,
		EntropyBits: flagHDWalletEntropyBits,
	}

	resp, err := c.EVM.HDWallets.Create(cmd.Context(), req)
	if err != nil {
		return fmt.Errorf("create hd wallet: %w", err)
	}
	return printJSON(resp)
}

// --- hdwallet import ---

var hdwalletImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an HD wallet from mnemonic",
	RunE:  runHDWalletImport,
}

var flagHDWalletMnemonic string

func runHDWalletImport(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	req := &evm.CreateHDWalletRequest{
		Password: flagHDWalletPassword,
		Mnemonic: flagHDWalletMnemonic,
	}

	resp, err := c.EVM.HDWallets.Import(cmd.Context(), req)
	if err != nil {
		return fmt.Errorf("import hd wallet: %w", err)
	}
	return printJSON(resp)
}

// --- hdwallet derive ---

var hdwalletDeriveCmd = &cobra.Command{
	Use:   "derive <primary-address>",
	Short: "Derive address(es) from an HD wallet",
	Args:  cobra.ExactArgs(1),
	RunE:  runHDWalletDerive,
}

var (
	flagHDWalletDeriveIndex int
	flagHDWalletDeriveStart int
	flagHDWalletDeriveCount int
)

func runHDWalletDerive(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	req := &evm.DeriveAddressRequest{}
	if cmd.Flags().Changed("index") {
		idx := uint32(flagHDWalletDeriveIndex) // #nosec G115 -- validated by cobra int flag
		req.Index = &idx
	}
	if cmd.Flags().Changed("start") {
		s := uint32(flagHDWalletDeriveStart) // #nosec G115
		req.Start = &s
	}
	if cmd.Flags().Changed("count") {
		cnt := uint32(flagHDWalletDeriveCount) // #nosec G115
		req.Count = &cnt
	}

	resp, err := c.EVM.HDWallets.DeriveAddress(cmd.Context(), args[0], req)
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}

	if flagOutputFormat == "json" {
		return printJSON(resp)
	}

	printTable(
		[]string{"ADDRESS", "TYPE", "ENABLED", "LOCKED"},
		func() [][]string {
			rows := make([][]string, len(resp.Derived))
			for i, d := range resp.Derived {
				rows[i] = []string{
					d.Address, d.Type,
					strconv.FormatBool(d.Enabled),
					strconv.FormatBool(d.Locked),
				}
			}
			return rows
		}(),
	)
	return nil
}

// --- hdwallet list-derived ---

var hdwalletListDerivedCmd = &cobra.Command{
	Use:   "list-derived <primary-address>",
	Short: "List derived addresses for an HD wallet",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.EVM.HDWallets.ListDerived(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("list derived addresses: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		printTable(
			[]string{"ADDRESS", "TYPE", "ENABLED", "LOCKED"},
			func() [][]string {
				rows := make([][]string, len(resp.Derived))
				for i, d := range resp.Derived {
					rows[i] = []string{
						d.Address, d.Type,
						strconv.FormatBool(d.Enabled),
						strconv.FormatBool(d.Locked),
					}
				}
				return rows
			}(),
		)
		return nil
	},
}

// --- registration ---

func init() {
	// create flags
	hdwalletCreateCmd.Flags().StringVar(&flagHDWalletPassword, "password", "", "Wallet encryption password")
	if err := hdwalletCreateCmd.MarkFlagRequired("password"); err != nil {
		panic(err)
	}
	hdwalletCreateCmd.Flags().IntVar(&flagHDWalletEntropyBits, "entropy-bits", 0, "Entropy bits for mnemonic generation (128, 256)")

	// import flags (reuses flagHDWalletPassword)
	hdwalletImportCmd.Flags().StringVar(&flagHDWalletPassword, "password", "", "Wallet encryption password")
	hdwalletImportCmd.Flags().StringVar(&flagHDWalletMnemonic, "mnemonic", "", "BIP-39 mnemonic phrase")
	if err := hdwalletImportCmd.MarkFlagRequired("password"); err != nil {
		panic(err)
	}
	if err := hdwalletImportCmd.MarkFlagRequired("mnemonic"); err != nil {
		panic(err)
	}

	// derive flags
	hdwalletDeriveCmd.Flags().IntVar(&flagHDWalletDeriveIndex, "index", 0, "Derive a single address at this index")
	hdwalletDeriveCmd.Flags().IntVar(&flagHDWalletDeriveStart, "start", 0, "Start index for batch derivation")
	hdwalletDeriveCmd.Flags().IntVar(&flagHDWalletDeriveCount, "count", 0, "Number of addresses to derive in batch")

	hdwalletCmd.AddCommand(hdwalletListCmd)
	hdwalletCmd.AddCommand(hdwalletCreateCmd)
	hdwalletCmd.AddCommand(hdwalletImportCmd)
	hdwalletCmd.AddCommand(hdwalletDeriveCmd)
	hdwalletCmd.AddCommand(hdwalletListDerivedCmd)

}
