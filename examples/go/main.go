// Example: Remote Signer Go Client with TLS/mTLS
//
// This example demonstrates how to use the Go client SDK to interact with
// a remote-signer service, including TLS and mTLS configuration.
//
// Usage:
//
//	# Set environment variables
//	export REMOTE_SIGNER_URL=https://localhost:8549
//	export REMOTE_SIGNER_API_KEY_ID=dev-key-1
//	export REMOTE_SIGNER_PRIVATE_KEY=<your-ed25519-private-key-hex>
//
//	# Run with mTLS
//	go run main.go \
//	  --ca-cert ../../certs/ca.crt \
//	  --client-cert ../../certs/client.crt \
//	  --client-key ../../certs/client.key
//
//	# Run without TLS (plain HTTP)
//	REMOTE_SIGNER_URL=http://localhost:8548 go run main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func main() {
	// CLI flags
	caCert := flag.String("ca-cert", "", "Path to CA certificate (for self-signed server certs)")
	clientCert := flag.String("client-cert", "", "Path to client certificate (for mTLS)")
	clientKey := flag.String("client-key", "", "Path to client private key (for mTLS)")
	skipVerify := flag.Bool("skip-verify", false, "Skip server certificate verification (insecure, testing only)")
	flag.Parse()

	// Read config from environment
	baseURL := os.Getenv("REMOTE_SIGNER_URL")
	if baseURL == "" {
		baseURL = "https://localhost:8549"
	}
	apiKeyID := os.Getenv("REMOTE_SIGNER_API_KEY_ID")
	if apiKeyID == "" {
		log.Fatal("REMOTE_SIGNER_API_KEY_ID environment variable is required")
	}
	privateKey := os.Getenv("REMOTE_SIGNER_PRIVATE_KEY")
	if privateKey == "" {
		log.Fatal("REMOTE_SIGNER_PRIVATE_KEY environment variable is required")
	}

	// Build client config
	cfg := client.Config{
		BaseURL:       baseURL,
		APIKeyID:      apiKeyID,
		PrivateKeyHex: privateKey,
		PollInterval:  2 * time.Second,
		PollTimeout:   5 * time.Minute,
	}

	// TLS configuration
	if *caCert != "" {
		cfg.TLSCAFile = *caCert
	}
	if *clientCert != "" {
		cfg.TLSCertFile = *clientCert
	}
	if *clientKey != "" {
		cfg.TLSKeyFile = *clientKey
	}
	if *skipVerify {
		cfg.TLSSkipVerify = true
	}

	// Create client
	c, err := client.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// 1. Health check
	fmt.Println("=== Health Check ===")
	health, err := c.Health(ctx)
	if err != nil {
		log.Fatalf("Health check failed: %v", err)
	}
	fmt.Printf("Status: %s, Version: %s\n\n", health.Status, health.Version)

	// 2. List signers
	fmt.Println("=== List Signers ===")
	signers, err := c.EVM.Signers.List(ctx, nil)
	if err != nil {
		log.Fatalf("List signers failed: %v", err)
	}
	for _, s := range signers.Signers {
		fmt.Printf("  Address: %s, Type: %s, Enabled: %v\n", s.Address, s.Type, s.Enabled)
	}
	fmt.Println()

	// 3. List requests
	fmt.Println("=== List Requests ===")
	requests, err := c.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
		Limit: 5,
	})
	if err != nil {
		log.Fatalf("List requests failed: %v", err)
	}
	fmt.Printf("Total: %d\n", requests.Total)
	for _, r := range requests.Requests {
		fmt.Printf("  ID: %s, Status: %s, SignType: %s\n", r.ID, r.Status, r.SignType)
	}
	fmt.Println()

	// 4. Sign a personal message (will need approval if no matching rule)
	fmt.Println("=== Sign Personal Message ===")
	if len(signers.Signers) > 0 {
		signer := signers.Signers[0]
		fmt.Printf("Using signer: %s\n", signer.Address)

		payload, _ := json.Marshal(evm.MessagePayload{
			Message: "Hello from Go client example!",
		})
		resp, err := c.EVM.Sign.ExecuteAsync(ctx, &evm.SignRequest{
			ChainID:      "1",
			SignerAddress: signer.Address,
			SignType:      evm.SignTypePersonal,
			Payload:       payload,
		})
		if err != nil {
			fmt.Printf("Sign result: %v\n", err)
		} else {
			fmt.Printf("Request ID: %s, Status: %s\n", resp.RequestID, resp.Status)
			if resp.Signature != "" {
				fmt.Printf("Signature: %s\n", resp.Signature)
			}
		}
	} else {
		fmt.Println("No signers available. Skipping sign example.")
	}

	fmt.Println("\nDone!")
}
