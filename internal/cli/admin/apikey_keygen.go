package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// `api-key keygen` generates an Ed25519 keypair locally — no contact with
// the remote-signer service. Use this when an operator needs to mint a new
// API credential before registering it via `api-key create --public-key …`.

var (
	flagKeygenOut       string
	flagKeygenForce     bool
	flagKeygenPubOnly   bool
	flagKeygenStdoutPub bool
)

var apiKeyKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 API key locally (no server contact)",
	Long: `Generate an Ed25519 keypair and write it to disk as PEM. Use the public
key (printed to stdout in hex) with 'api-key create --public-key …' to register
it with a remote-signer instance.

By default writes <out>.priv (0600) and <out>.pub (0644) next to each other.`,
	RunE: runAPIKeyKeygen,
}

func runAPIKeyKeygen(_ *cobra.Command, _ []string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	pubHex := hex.EncodeToString(pub)
	if flagKeygenStdoutPub {
		fmt.Println(pubHex)
		return nil
	}

	out := flagKeygenOut
	if out == "" {
		return fmt.Errorf("--out is required (or pass --print-public to skip files)")
	}
	out = strings.TrimSuffix(out, ".priv")
	out = strings.TrimSuffix(out, ".pub")
	privPath := out + ".priv"
	pubPath := out + ".pub"

	if !flagKeygenForce {
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s already exists; pass --force to overwrite", p)
			}
		}
	}

	if dir := filepath.Dir(privPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
	}

	privPEM, err := encodeEd25519PrivKeygen(priv)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}

	if !flagKeygenPubOnly {
		pubPEM, err := encodeEd25519PubKeygen(pub)
		if err != nil {
			_ = os.Remove(privPath)
			return fmt.Errorf("encode public key: %w", err)
		}
		if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
			_ = os.Remove(privPath)
			return fmt.Errorf("write %s: %w", pubPath, err)
		}
	}

	fmt.Println("Generated Ed25519 API keypair.")
	fmt.Println("  Private key file:  " + privPath + "  (chmod 600)")
	if !flagKeygenPubOnly {
		fmt.Println("  Public key file:   " + pubPath)
	}
	fmt.Println("  Public key (hex):  " + pubHex)
	fmt.Println("")
	fmt.Println("Register with the service:")
	fmt.Println("  remote-signer api-key create --id <id> --name <name> --public-key " + pubHex)
	return nil
}

func encodeEd25519PrivKeygen(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodeEd25519PubKeygen(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func init() {
	apiKeyKeygenCmd.Flags().StringVar(&flagKeygenOut, "out", "", "Output path (writes <out>.priv and <out>.pub)")
	apiKeyKeygenCmd.Flags().BoolVar(&flagKeygenForce, "force", false, "Overwrite existing files")
	apiKeyKeygenCmd.Flags().BoolVar(&flagKeygenPubOnly, "no-pub-file", false, "Skip writing the .pub file (still print hex)")
	apiKeyKeygenCmd.Flags().BoolVar(&flagKeygenStdoutPub, "print-public", false, "Print only the public key hex to stdout; do not write files")

	apiKeyCmd.AddCommand(apiKeyKeygenCmd)
}
