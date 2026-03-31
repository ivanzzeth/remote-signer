// One-off command to verify Polymarket setup flow: createProxy sign (safe_init preset)
// then after adding full preset and restarting server, a trading-style sign.
//
// Usage:
//
//	# 1) createProxy sign (server must be running with polymarket_safe_init preset, signer created via TUI)
//	go run ./cmd/remote-signer-verify-setup-polymarket -step createproxy -signer 0x4F2fE52763B4E89afC5bB061644d60Cd3C488717
//
//	# 2) Add full preset and restart server, then run trading sign:
//	go run ./cmd/remote-signer-verify-setup-polymarket -step trade -signer 0x4F2fE52763B4E89afC5bB061644d60Cd3C488717
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"crypto/ed25519"
	"crypto/x509"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

const (
	safeFactoryPolygon = "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b"
	chainIDPolygon     = "137"
	// createProxy(paymentToken=0, payment=0, paymentReceiver=0, sig=(0,0,0)) — zero payment, placeholder sig
	createProxyCalldata = "0xa1884d2c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	// USDC.e approve to CTF Exchange (for trading step)
	usdcApproveCalldata = "0x095ea7b30000000000000000000000004bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982Effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	usdcPolygon         = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
)

func main() {
	step := flag.String("step", "createproxy", "createproxy | trade")
	signerAddr := flag.String("signer", "0x4F2fE52763B4E89afC5bB061644d60Cd3C488717", "Signer address (from TUI)")
	apiKeyFile := flag.String("api-key-file", "data/admin_private.pem", "Path to admin API key PEM")
	baseURL := flag.String("url", "http://localhost:8548", "Server base URL")
	flag.Parse()

	keyHex, err := loadPrivateKeyFromFile(*apiKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load API key: %v\n", err)
		os.Exit(1)
	}

	cfg := client.Config{
		BaseURL:       *baseURL,
		APIKeyID:      "admin",
		PrivateKeyHex: keyHex,
	}
	c, err := client.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "new client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	switch *step {
	case "createproxy":
		if err := runCreateProxy(ctx, c, *signerAddr); err != nil {
			fmt.Fprintf(os.Stderr, "createProxy sign: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("createProxy sign: OK (not broadcast)")
	case "trade":
		if err := runTrade(ctx, c, *signerAddr); err != nil {
			fmt.Fprintf(os.Stderr, "trade sign: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("trade sign: OK")
	default:
		fmt.Fprintf(os.Stderr, "unknown step %q (createproxy | trade)\n", *step)
		os.Exit(1)
	}
}

func runCreateProxy(ctx context.Context, c *client.Client, signer string) error {
	payload := map[string]interface{}{
		"transaction": map[string]interface{}{
			"to":       safeFactoryPolygon,
			"value":    "0",
			"data":     createProxyCalldata,
			"gas":      uint64(300000),
			"gasPrice": "0",
			"txType":   "legacy",
		},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req := &evm.SignRequest{
		ChainID:       chainIDPolygon,
		SignerAddress: signer,
		SignType:      evm.SignTypeTransaction,
		Payload:       payloadBytes,
	}
	resp, err := c.EVM.Sign.Execute(ctx, req)
	if err != nil {
		return err
	}
	if resp.Status != evm.StatusCompleted {
		return fmt.Errorf("status %s: %s", resp.Status, resp.Message)
	}
	if resp.SignedData == "" {
		return fmt.Errorf("no signed_data in response")
	}
	// Decode and show length only (raw signed tx)
	b, _ := hex.DecodeString(strings.TrimPrefix(resp.SignedData, "0x"))
	fmt.Printf("signed_tx length: %d bytes\n", len(b))
	return nil
}

func runTrade(ctx context.Context, c *client.Client, signer string) error {
	// Simple USDC approve transaction (allowed by full preset trading rules when Safe is set)
	payload := map[string]interface{}{
		"transaction": map[string]interface{}{
			"to":       usdcPolygon,
			"value":    "0",
			"data":     usdcApproveCalldata,
			"gas":      uint64(100000),
			"gasPrice": "0",
			"txType":   "legacy",
		},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req := &evm.SignRequest{
		ChainID:       chainIDPolygon,
		SignerAddress: signer,
		SignType:      evm.SignTypeTransaction,
		Payload:       payloadBytes,
	}
	resp, err := c.EVM.Sign.Execute(ctx, req)
	if err != nil {
		return err
	}
	if resp.Status != evm.StatusCompleted {
		return fmt.Errorf("status %s: %s", resp.Status, resp.Message)
	}
	fmt.Printf("signature/signed_data present: %v\n", resp.Signature != "" || resp.SignedData != "")
	return nil
}

func loadPrivateKeyFromFile(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		var err error
		cleanPath, err = filepath.Abs(cleanPath)
		if err != nil {
			return "", err
		}
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block in %s", path)
	}
	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	ed, ok := pk.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key is not Ed25519")
	}
	return hex.EncodeToString(ed), nil
}
