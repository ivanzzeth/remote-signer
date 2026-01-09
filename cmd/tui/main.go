package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/tui"
)

func main() {
	// Parse flags
	var (
		baseURL    = flag.String("url", "http://localhost:8548", "Remote signer service URL")
		apiKeyID   = flag.String("api-key-id", "", "API key ID for authentication")
		privateKey = flag.String("private-key", "", "Ed25519 private key in hex or base64 (or set REMOTE_SIGNER_PRIVATE_KEY env)")
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

	if *privateKey == "" {
		*privateKey = os.Getenv("REMOTE_SIGNER_PRIVATE_KEY")
	}
	if *privateKey == "" {
		fmt.Fprintln(os.Stderr, "Error: Private key is required. Use -private-key flag or set REMOTE_SIGNER_PRIVATE_KEY environment variable.")
		os.Exit(1)
	}

	if *baseURL == "" {
		*baseURL = os.Getenv("REMOTE_SIGNER_URL")
	}
	if *baseURL == "" {
		*baseURL = "http://localhost:8548"
	}

	// Detect key format: hex (64+ hex chars) or base64
	cfg := client.Config{
		BaseURL:  *baseURL,
		APIKeyID: *apiKeyID,
	}
	if isHexKey(*privateKey) {
		cfg.PrivateKeyHex = *privateKey
	} else {
		cfg.PrivateKeyBase64 = *privateKey
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
