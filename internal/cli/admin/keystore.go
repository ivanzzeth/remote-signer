package admin

import (
	"context"
	"fmt"
	"os"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/spf13/cobra"

	"github.com/ivanzzeth/remote-signer/internal/homepath"
)

// The keystore subcommand exists in two places:
//
//   - Top-level `remote-signer keystore` operates on chain-side signer
//     keystores (secp256k1 by default) and defaults --dir to
//     ~/.remote-signer/keystores/.
//   - `remote-signer api-key keystore` operates on the Ed25519 keystores
//     used to authenticate to the daemon's HTTP API and defaults --dir to
//     ~/.remote-signer/apikeys/.
//
// Both trees share the same RunE handlers via builder functions below; only
// the default value of --dir and the default --key-type on `create` differ.
// All read-side commands (list/show/verify/export/change-password) are
// key-type agnostic — the keystore JSON carries its own KeyType field.

// keystore flag variables (package-level so both subtrees write into the
// same memory; only one cobra command runs per invocation, so the alias
// path uses these without coordinating extra state).
var (
	flagKeystoreDir     string
	flagKeystorePath    string
	flagKeystoreLabel   string
	flagKeystoreFormat  string
	flagKeystoreKeyType string
)

func defaultSignerKeystoreDir() string {
	if dir, err := homepath.SignerKeystoresDir(); err == nil {
		return dir
	}
	return "./data/keystores"
}

func defaultAPIKeysDir() string {
	if dir, err := homepath.APIKeysDir(); err == nil {
		return dir
	}
	return "./data/apikeys"
}

// resolveKeyType maps the CLI string to ethsig's typed enum. Defaults to
// Ed25519 when empty — the api-key subtree relies on that default; the
// signer subtree sets --key-type=secp256k1 explicitly.
func resolveKeyType(s string) (keystore.KeyType, error) {
	switch s {
	case "", "ed25519":
		return keystore.KeyTypeEd25519, nil
	case "secp256k1":
		return keystore.KeyTypeSecp256k1, nil
	case "p256":
		return keystore.KeyTypeP256, nil
	default:
		return "", fmt.Errorf("unsupported key type %q (use ed25519, secp256k1, or p256)", s)
	}
}

// -- shared handlers --------------------------------------------------------

func runKeystoreCreate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	keyType, err := resolveKeyType(flagKeystoreKeyType)
	if err != nil {
		return err
	}

	password, err := readKeystorePassword(ctx)
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	defer keystore.SecureZeroize(password)

	// MkdirAll(0700) so the first `keystore create` against a fresh
	// install just works whether the default points at apikeys/ or
	// keystores/ — neither is guaranteed to exist before the daemon ran.
	if err := os.MkdirAll(flagKeystoreDir, 0700); err != nil {
		return fmt.Errorf("create keystore dir %s: %w", flagKeystoreDir, err)
	}

	identifier, path, err := keystore.CreateEnhancedKey(
		flagKeystoreDir,
		keyType,
		password,
		flagKeystoreLabel,
	)
	if err != nil {
		return fmt.Errorf("create keystore: %w", err)
	}

	fmt.Printf("Created %s keystore\n", keyType)
	fmt.Printf("  Identifier (public key): %s\n", identifier)
	fmt.Printf("  Path: %s\n", path)
	if flagKeystoreLabel != "" {
		fmt.Printf("  Label: %s\n", flagKeystoreLabel)
	}
	return nil
}

func runKeystoreList(cmd *cobra.Command, args []string) error {
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
}

func runKeystoreShow(cmd *cobra.Command, args []string) error {
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
}

func runKeystoreExport(cmd *cobra.Command, args []string) error {
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
}

func runKeystoreVerify(cmd *cobra.Command, args []string) error {
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
}

func runKeystoreChangePassword(cmd *cobra.Command, args []string) error {
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
}

// -- builders --------------------------------------------------------------

// keystoreSubtreeOptions tunes a built keystore subtree. Different
// invocations (top-level vs api-key) supply different defaults.
type keystoreSubtreeOptions struct {
	defaultDir     string
	defaultKeyType string // ed25519 for api-key subtree, secp256k1 for top-level
	shortHint      string // appended to subcommand long-descriptions
}

// buildKeystoreSubtree returns a fresh keystore parent command populated
// with create/list/show/export/verify/change-password subcommands. Each
// invocation gets its own *cobra.Command instances so the same handlers
// can be mounted under two different parents with different defaults.
func buildKeystoreSubtree(opts keystoreSubtreeOptions) *cobra.Command {
	parent := &cobra.Command{
		Use:   "keystore",
		Short: "Manage encrypted Ed25519/secp256k1 keystores" + opts.shortHint,
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new encrypted keystore",
		RunE:  runKeystoreCreate,
	}
	createCmd.Flags().StringVarP(&flagKeystoreDir, "dir", "d", opts.defaultDir, "Directory to store keystore files")
	createCmd.Flags().StringVar(&flagKeystoreLabel, "label", "", "Optional label for the keystore")
	createCmd.Flags().StringVar(&flagKeystoreKeyType, "key-type", opts.defaultKeyType, "Key type: ed25519, secp256k1, p256")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List keystores in a directory",
		RunE:  runKeystoreList,
	}
	listCmd.Flags().StringVarP(&flagKeystoreDir, "dir", "d", opts.defaultDir, "Directory containing keystore files")

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show keystore metadata (no password required)",
		RunE:  runKeystoreShow,
	}
	showCmd.Flags().StringVarP(&flagKeystorePath, "keystore", "k", "", "Path to keystore file")
	if err := showCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Decrypt and export the private key",
		RunE:  runKeystoreExport,
	}
	exportCmd.Flags().StringVarP(&flagKeystorePath, "keystore", "k", "", "Path to keystore file")
	if err := exportCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}
	exportCmd.Flags().StringVar(&flagKeystoreFormat, "format", "hex", "Output format: hex, base64, pem")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the keystore password is correct",
		RunE:  runKeystoreVerify,
	}
	verifyCmd.Flags().StringVarP(&flagKeystorePath, "keystore", "k", "", "Path to keystore file")
	if err := verifyCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	changeCmd := &cobra.Command{
		Use:   "change-password",
		Short: "Change the keystore password",
		RunE:  runKeystoreChangePassword,
	}
	changeCmd.Flags().StringVarP(&flagKeystorePath, "keystore", "k", "", "Path to keystore file")
	if err := changeCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	parent.AddCommand(createCmd, listCmd, showCmd, exportCmd, verifyCmd, changeCmd)
	return parent
}

// -- registration ----------------------------------------------------------

// keystoreCmd is the top-level subtree (`remote-signer keystore ...`).
// Defaults aim at chain-side signer keystores (secp256k1, ~/.remote-signer/keystores/).
var keystoreCmd = buildKeystoreSubtree(keystoreSubtreeOptions{
	defaultDir:     defaultSignerKeystoreDir(),
	defaultKeyType: "secp256k1",
	shortHint:      " (default: ~/.remote-signer/keystores/, signer keys)",
})

// apiKeystoreCmd mirrors keystoreCmd under `api-key keystore ...` with the
// defaults flipped for API authentication keystores.
var apiKeystoreCmd = buildKeystoreSubtree(keystoreSubtreeOptions{
	defaultDir:     defaultAPIKeysDir(),
	defaultKeyType: "ed25519",
	shortHint:      " (default: ~/.remote-signer/apikeys/, API auth keys)",
})

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

func init() {
	// Mount the api-key keystore alias under the existing api-key subtree.
	apiKeyCmd.AddCommand(apiKeystoreCmd)
}
