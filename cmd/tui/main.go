package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/tui"
)

func main() {
	// Parse flags
	var (
		baseURL       = flag.String("url", "https://localhost:8548", "Remote signer service URL")
		apiKeyID      = flag.String("api-key-id", "", "API key ID for authentication")
		tlsCA         = flag.String("tls-ca", "", "Path to CA certificate to verify server (for HTTPS)")
		tlsCert       = flag.String("tls-cert", "", "Path to client certificate (for mTLS)")
		tlsKey        = flag.String("tls-key", "", "Path to client private key (for mTLS)")
		tlsSkipVerify = flag.Bool("tls-skip-verify", false, "Skip server certificate verification (insecure, testing only)")
	)
	flag.Parse()

	// Validate required parameters
	if *apiKeyID == "" {
		*apiKeyID = os.Getenv("REMOTE_SIGNER_API_KEY_ID")
	}
	if *apiKeyID == "" {
		fmt.Fprintln(os.Stderr, "Error: API key ID is required. Use -api-key-id flag or set REMOTE_SIGNER_API_KEY_ID environment variable.")
		os.Exit(1)
	}

	// Resolve private key: env var first, then interactive prompt
	privateKey := os.Getenv("REMOTE_SIGNER_PRIVATE_KEY")
	if privateKey == "" {
		key, err := readPrivateKeyFromPrompt()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading private key: %v\n", err)
			os.Exit(1)
		}
		privateKey = key
	}

	if *baseURL == "" {
		*baseURL = os.Getenv("REMOTE_SIGNER_URL")
	}
	if *baseURL == "" {
		*baseURL = "https://localhost:8548"
	}

	// TLS: env then defaults for HTTPS. When URL is https:// and no TLS flags/env set, use certs/ in current directory (same layout as scripts/gen-certs.sh: ca.crt, client.crt, client.key).
	if *tlsCA == "" {
		*tlsCA = os.Getenv("REMOTE_SIGNER_TLS_CA_FILE")
	}
	if *tlsCert == "" {
		*tlsCert = os.Getenv("REMOTE_SIGNER_TLS_CERT_FILE")
	}
	if *tlsKey == "" {
		*tlsKey = os.Getenv("REMOTE_SIGNER_TLS_KEY_FILE")
	}
	if strings.HasPrefix(*baseURL, "https://") && *tlsCA == "" && *tlsCert == "" && *tlsKey == "" && !*tlsSkipVerify {
		*tlsCA = "certs/ca.crt"
		*tlsCert = "certs/client.crt"
		*tlsKey = "certs/client.key"
	}
	if !*tlsSkipVerify && os.Getenv("REMOTE_SIGNER_TLS_SKIP_VERIFY") == "1" {
		*tlsSkipVerify = true
	}

	// Detect key format: hex (64+ hex chars) or base64
	cfg := client.Config{
		BaseURL:       *baseURL,
		APIKeyID:      *apiKeyID,
		TLSCAFile:     *tlsCA,
		TLSCertFile:   *tlsCert,
		TLSKeyFile:    *tlsKey,
		TLSSkipVerify: *tlsSkipVerify,
	}
	if isHexKey(privateKey) {
		cfg.PrivateKeyHex = privateKey
	} else {
		cfg.PrivateKeyBase64 = privateKey
	}

	// Create client
	c, err := client.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	// Create TUI model
	model, err := tui.NewModel(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating TUI: %v\n", err)
		os.Exit(1)
	}

	// Run the TUI
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

// readPrivateKeyFromPrompt securely reads the private key from the terminal
// without echoing characters.
func readPrivateKeyFromPrompt() (string, error) {
	fmt.Fprint(os.Stderr, "Enter Ed25519 private key (hex or base64): ")
	keyBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return "", fmt.Errorf("failed to read from terminal: %w", err)
	}
	key := strings.TrimSpace(string(keyBytes))
	if key == "" {
		return "", fmt.Errorf("private key cannot be empty")
	}
	return key, nil
}

// isHexKey checks if the key appears to be hex encoded (64+ hex characters)
// vs base64 encoded (contains non-hex characters like +, /, =, or uppercase letters beyond F)
func isHexKey(key string) bool {
	key = strings.TrimPrefix(key, "0x")

	// If it's a valid hex string of expected length for Ed25519 (64 or 128 chars), treat as hex
	if len(key) >= 64 {
		for _, c := range key {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}

	// Otherwise, try to decode as base64 to see if it's valid
	_, err := base64.StdEncoding.DecodeString(key)
	return err != nil // If base64 decode fails, assume hex
}
