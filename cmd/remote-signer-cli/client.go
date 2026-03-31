package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/spf13/cobra"
)

// Auth flag variables (bound to persistent flags on rootCmd)
var (
	flagURL              string
	flagAPIKeyID         string
	flagAPIKeyFile       string
	flagAPIKeyKeystore   string
	flagAPIKeyPasswordEnv string
	flagTLSCA            string
	flagTLSCert          string
	flagTLSKey           string
	flagTLSSkipVerify    bool
	flagOutputFormat     string
	flagJSON             bool
)

// registerAuthFlags adds persistent auth flags to the root command.
func registerAuthFlags(rootCmd *cobra.Command) {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagURL, "url", "https://localhost:8548", "Remote signer server URL")
	pf.StringVar(&flagAPIKeyID, "api-key-id", "", "API key ID for authentication")
	pf.StringVar(&flagAPIKeyFile, "api-key-file", "", "Path to Ed25519 private key PEM file")
	pf.StringVar(&flagAPIKeyKeystore, "api-key-keystore", "", "Path to Ed25519 encrypted keystore file (mutually exclusive with --api-key-file)")
	pf.StringVar(&flagAPIKeyPasswordEnv, "api-key-password-env", "", "Environment variable name containing the keystore password (for CI; default: interactive prompt)")
	pf.StringVar(&flagTLSCA, "tls-ca", "", "CA certificate for TLS verification")
	pf.StringVar(&flagTLSCert, "tls-cert", "", "Client certificate for mTLS")
	pf.StringVar(&flagTLSKey, "tls-key", "", "Client key for mTLS")
	pf.BoolVar(&flagTLSSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (testing only)")
	pf.StringVarP(&flagOutputFormat, "output", "o", "table", "Output format: table, json, yaml")
	pf.BoolVar(&flagJSON, "json", false, "Machine-readable JSON output (sets -o json; PRD agent output)")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if flagJSON {
			flagOutputFormat = "json"
		}
	}
}

// newClientFromFlags creates a pkg/client.Client using the persistent auth flags.
func newClientFromFlags(cmd *cobra.Command) (*client.Client, error) {
	if flagAPIKeyID == "" {
		return nil, fmt.Errorf("--api-key-id is required")
	}
	if flagAPIKeyFile != "" && flagAPIKeyKeystore != "" {
		return nil, fmt.Errorf("--api-key-file and --api-key-keystore are mutually exclusive")
	}
	if flagAPIKeyFile == "" && flagAPIKeyKeystore == "" {
		return nil, fmt.Errorf("one of --api-key-file or --api-key-keystore is required")
	}

	var privKey ed25519.PrivateKey
	if flagAPIKeyKeystore != "" {
		key, err := loadEd25519FromKeystore(cmd, flagAPIKeyKeystore)
		if err != nil {
			return nil, fmt.Errorf("failed to load key from keystore %s: %w", flagAPIKeyKeystore, err)
		}
		privKey = key
	} else {
		key, err := loadEd25519PrivateKey(flagAPIKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key from %s: %w", flagAPIKeyFile, err)
		}
		privKey = key
	}

	cfg := client.Config{
		BaseURL:       flagURL,
		APIKeyID:      flagAPIKeyID,
		PrivateKey:    privKey,
		TLSCAFile:     flagTLSCA,
		TLSCertFile:   flagTLSCert,
		TLSKeyFile:    flagTLSKey,
		TLSSkipVerify: flagTLSSkipVerify,
	}

	return client.NewClient(cfg)
}

// loadEd25519FromKeystore decrypts an ethsig encrypted keystore to get the Ed25519 private key.
func loadEd25519FromKeystore(cmd *cobra.Command, keystorePath string) (ed25519.PrivateKey, error) {
	password, err := resolveKeystorePassword(cmd)
	if err != nil {
		return nil, fmt.Errorf("resolve keystore password: %w", err)
	}
	defer keystore.SecureZeroize(password)

	seedBytes, err := keystore.ExportEnhancedKey(keystorePath, password, keystore.KeyFormatHex)
	if err != nil {
		return nil, fmt.Errorf("decrypt keystore: %w", err)
	}
	defer keystore.SecureZeroize(seedBytes)

	// seedBytes is hex-encoded; parse back to raw bytes
	rawSeed, err := keystore.ParseKeyInput(seedBytes, keystore.KeyFormatHex, keystore.KeyTypeEd25519)
	if err != nil {
		return nil, fmt.Errorf("parse seed from keystore: %w", err)
	}
	defer keystore.SecureZeroize(rawSeed)

	return ed25519.NewKeyFromSeed(rawSeed), nil
}

// resolveKeystorePassword gets the password from --api-key-password-env or interactive prompt.
func resolveKeystorePassword(cmd *cobra.Command) ([]byte, error) {
	if flagAPIKeyPasswordEnv != "" {
		envVal := os.Getenv(flagAPIKeyPasswordEnv)
		if envVal == "" {
			return nil, fmt.Errorf("environment variable %s is empty or not set", flagAPIKeyPasswordEnv)
		}
		return []byte(envVal), nil
	}

	fmt.Fprint(os.Stderr, "Enter keystore password: ")
	return keystore.ReadSecret(cmd.Context())
}

// loadEd25519PrivateKey reads a PEM file and extracts the Ed25519 private key.
func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath) // #nosec G304 -- user-provided CLI flag, path cleaned
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
	}
	return edKey, nil
}
