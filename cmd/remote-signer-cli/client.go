package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/spf13/cobra"
)

// Auth flag variables (bound to persistent flags on rootCmd)
var (
	flagURL           string
	flagAPIKeyID      string
	flagAPIKeyFile    string
	flagTLSCA         string
	flagTLSCert       string
	flagTLSKey        string
	flagTLSSkipVerify bool
	flagOutputFormat  string
)

// registerAuthFlags adds persistent auth flags to the root command.
func registerAuthFlags(rootCmd *cobra.Command) {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagURL, "url", "https://localhost:8548", "Remote signer server URL")
	pf.StringVar(&flagAPIKeyID, "api-key-id", "", "API key ID for authentication")
	pf.StringVar(&flagAPIKeyFile, "api-key-file", "", "Path to Ed25519 private key PEM file")
	pf.StringVar(&flagTLSCA, "tls-ca", "", "CA certificate for TLS verification")
	pf.StringVar(&flagTLSCert, "tls-cert", "", "Client certificate for mTLS")
	pf.StringVar(&flagTLSKey, "tls-key", "", "Client key for mTLS")
	pf.BoolVar(&flagTLSSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (testing only)")
	pf.StringVarP(&flagOutputFormat, "output", "o", "table", "Output format: table, json, yaml")
}

// newClientFromFlags creates a pkg/client.Client using the persistent auth flags.
func newClientFromFlags(cmd *cobra.Command) (*client.Client, error) {
	if flagAPIKeyID == "" {
		return nil, fmt.Errorf("--api-key-id is required")
	}
	if flagAPIKeyFile == "" {
		return nil, fmt.Errorf("--api-key-file is required")
	}

	privKey, err := loadEd25519PrivateKey(flagAPIKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key from %s: %w", flagAPIKeyFile, err)
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

// loadEd25519PrivateKey reads a PEM file and extracts the Ed25519 private key.
func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
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
