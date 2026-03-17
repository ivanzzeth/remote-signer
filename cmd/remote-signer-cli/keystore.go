package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/spf13/cobra"
)

// keystore flag variables
var (
	flagKeystoreDir    string
	flagKeystorePath   string
	flagKeystoreLabel  string
	flagKeystoreFormat string
)

var keystoreCmd = &cobra.Command{
	Use:   "keystore",
	Short: "Manage Ed25519 encrypted keystores for API key authentication",
}

// -- keystore create --------------------------------------------------------

var keystoreCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new Ed25519 encrypted keystore",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		password, err := readKeystorePassword(ctx)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		defer keystore.SecureZeroize(password)

		identifier, path, err := keystore.CreateEnhancedKey(
			flagKeystoreDir,
			keystore.KeyTypeEd25519,
			password,
			flagKeystoreLabel,
		)
		if err != nil {
			return fmt.Errorf("create keystore: %w", err)
		}

		fmt.Printf("Created Ed25519 keystore\n")
		fmt.Printf("  Identifier (public key): %s\n", identifier)
		fmt.Printf("  Path: %s\n", path)
		if flagKeystoreLabel != "" {
			fmt.Printf("  Label: %s\n", flagKeystoreLabel)
		}
		return nil
	},
}

// -- keystore list ----------------------------------------------------------

var keystoreListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all Ed25519 keystores in a directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		keys, err := keystore.ListEnhancedKeys(flagKeystoreDir)
		if err != nil {
			return fmt.Errorf("list keystores: %w", err)
		}

		if len(keys) == 0 {
			fmt.Println("No keystores found.")
			return nil
		}

		if flagOutputFormat == "json" {
			return printJSON(keys)
		}

		printTable(
			[]string{"IDENTIFIER", "KEY_TYPE", "LABEL", "PATH"},
			func() [][]string {
				rows := make([][]string, len(keys))
				for i, k := range keys {
					rows[i] = []string{k.Identifier, string(k.KeyType), k.Label, k.Path}
				}
				return rows
			}(),
		)
		return nil
	},
}

// -- keystore show ----------------------------------------------------------

var keystoreShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show keystore metadata (no password required)",
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := keystore.GetEnhancedKeyInfo(flagKeystorePath)
		if err != nil {
			return fmt.Errorf("read keystore info: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(info)
		}

		fmt.Printf("Keystore: %s\n", info.Path)
		fmt.Printf("  Key Type:   %s\n", info.KeyType)
		fmt.Printf("  Identifier: %s\n", info.Identifier)
		fmt.Printf("  Label:      %s\n", info.Label)
		return nil
	},
}

// -- keystore export --------------------------------------------------------

var keystoreExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Decrypt and export the private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		password, err := readKeystorePasswordSingle(ctx)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		defer keystore.SecureZeroize(password)

		format := keystore.KeyFormatHex
		switch flagKeystoreFormat {
		case "hex":
			format = keystore.KeyFormatHex
		case "base64":
			format = keystore.KeyFormatBase64
		case "pem":
			format = keystore.KeyFormatPEM
		default:
			return fmt.Errorf("unsupported format: %s (use hex, base64, or pem)", flagKeystoreFormat)
		}

		output, err := keystore.ExportEnhancedKey(flagKeystorePath, password, format)
		if err != nil {
			return fmt.Errorf("export key: %w", err)
		}
		defer keystore.SecureZeroize(output)

		fmt.Print(string(output))
		if format != keystore.KeyFormatPEM {
			fmt.Println()
		}
		return nil
	},
}

// -- keystore verify --------------------------------------------------------

var keystoreVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the keystore password is correct",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		password, err := readKeystorePasswordSingle(ctx)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		defer keystore.SecureZeroize(password)

		if err := keystore.VerifyEnhancedKeyPassword(flagKeystorePath, password); err != nil {
			return fmt.Errorf("verify password: %w", err)
		}

		fmt.Println("Password is correct.")
		return nil
	},
}

// -- keystore change-password -----------------------------------------------

var keystoreChangePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change the keystore password",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		fmt.Print("Current password: ")
		currentPassword, err := keystore.ReadSecret(ctx)
		if err != nil {
			return fmt.Errorf("read current password: %w", err)
		}
		defer keystore.SecureZeroize(currentPassword)

		newPassword, err := keystore.ReadPasswordWithConfirm(ctx, "New password")
		if err != nil {
			return fmt.Errorf("read new password: %w", err)
		}
		defer keystore.SecureZeroize(newPassword)

		if err := keystore.ChangeEnhancedKeyPassword(flagKeystorePath, currentPassword, newPassword); err != nil {
			return fmt.Errorf("change password: %w", err)
		}

		fmt.Println("Password changed successfully.")
		return nil
	},
}

// -- helpers ----------------------------------------------------------------

// readKeystorePassword reads a password with confirmation for create operations.
func readKeystorePassword(ctx context.Context) ([]byte, error) {
	envPassword := os.Getenv("REMOTE_SIGNER_KEYSTORE_PASSWORD")
	if envPassword != "" {
		return []byte(envPassword), nil
	}
	return keystore.ReadPasswordWithConfirm(ctx, "Enter password")
}

// readKeystorePasswordSingle reads a password without confirmation (for verify/export).
func readKeystorePasswordSingle(ctx context.Context) ([]byte, error) {
	envPassword := os.Getenv("REMOTE_SIGNER_KEYSTORE_PASSWORD")
	if envPassword != "" {
		return []byte(envPassword), nil
	}
	fmt.Print("Enter password: ")
	return keystore.ReadSecret(ctx)
}

// -- registration -----------------------------------------------------------

func init() {
	// create flags
	keystoreCreateCmd.Flags().StringVarP(&flagKeystoreDir, "dir", "d", "./data/apikeys", "Directory to store keystore files")
	keystoreCreateCmd.Flags().StringVar(&flagKeystoreLabel, "label", "", "Optional label for the keystore")

	// list flags
	keystoreListCmd.Flags().StringVarP(&flagKeystoreDir, "dir", "d", "./data/apikeys", "Directory containing keystore files")

	// show flags
	keystoreShowCmd.Flags().StringVarP(&flagKeystorePath, "keystore", "k", "", "Path to keystore file")
	if err := keystoreShowCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	// export flags
	keystoreExportCmd.Flags().StringVarP(&flagKeystorePath, "keystore", "k", "", "Path to keystore file")
	if err := keystoreExportCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}
	keystoreExportCmd.Flags().StringVar(&flagKeystoreFormat, "format", "hex", "Output format: hex, base64, pem")

	// verify flags
	keystoreVerifyCmd.Flags().StringVarP(&flagKeystorePath, "keystore", "k", "", "Path to keystore file")
	if err := keystoreVerifyCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	// change-password flags
	keystoreChangePasswordCmd.Flags().StringVarP(&flagKeystorePath, "keystore", "k", "", "Path to keystore file")
	if err := keystoreChangePasswordCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	keystoreCmd.AddCommand(keystoreCreateCmd)
	keystoreCmd.AddCommand(keystoreListCmd)
	keystoreCmd.AddCommand(keystoreShowCmd)
	keystoreCmd.AddCommand(keystoreExportCmd)
	keystoreCmd.AddCommand(keystoreVerifyCmd)
	keystoreCmd.AddCommand(keystoreChangePasswordCmd)
}
