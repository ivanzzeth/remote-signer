package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

func main() {
	pemData, err := os.ReadFile("data/api_dev_private.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(pemData)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	privKey := key.(ed25519.PrivateKey)

	pollInterval := 2 * time.Second
	pollTimeout := 5 * time.Second
	c, err := client.NewClient(client.Config{
		BaseURL:      "https://localhost:8548",
		APIKeyID:     "dev",
		PrivateKey:   privKey,
		TLSCertFile:  "certs/client.crt",
		TLSKeyFile:   "certs/client.key",
		TLSCAFile:    "certs/ca.crt",
		PollInterval: pollInterval,
		PollTimeout:  pollTimeout,
	})
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	signerAddr := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	chainID := "137"

	signTx := func(to, value, data string) error {
		tx := client.Transaction{To: &to, Value: value, Data: data, Gas: 100000, TxType: "legacy", GasPrice: "30000000000"}
		payload, _ := json.Marshal(client.TransactionPayload{Transaction: &tx})
		_, err := c.Sign(ctx, &client.SignRequest{
			ChainID: chainID, SignerAddress: signerAddr.Hex(),
			SignType: "transaction", Payload: payload,
		})
		return err
	}

	signPersonal := func(msg string) error {
		payload, _ := json.Marshal(client.MessagePayload{Message: msg})
		_, err := c.Sign(ctx, &client.SignRequest{
			ChainID: chainID, SignerAddress: signerAddr.Hex(),
			SignType: "personal", Payload: payload,
		})
		return err
	}

	signTypedData := func(td *client.TypedData) error {
		payload, _ := json.Marshal(client.TypedDataPayload{TypedData: td})
		_, err := c.Sign(ctx, &client.SignRequest{
			ChainID: chainID, SignerAddress: signerAddr.Hex(),
			SignType: "typed_data", Payload: payload,
		})
		return err
	}

	type testCase struct {
		name   string
		expect string
		fn     func() error
	}

	tests := []testCase{
		// --- Malicious: should all be rejected ---
		{
			name: "1. Transfer ETH to random address", expect: "reject",
			fn: func() error {
				return signTx("0xdead000000000000000000000000000000000001", "1000000000000000000", "0x")
			},
		},
		{
			name: "2. ERC20 transfer(random, 1M) on USDC", expect: "reject",
			fn: func() error {
				return signTx("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "0",
					"0xa9059cbb000000000000000000000000dead00000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000f4240")
			},
		},
		{
			name: "3. USDC approve to malicious spender", expect: "reject",
			fn: func() error {
				return signTx("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "0",
					"0x095ea7b3000000000000000000000000dead000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
			},
		},
		{
			name: "4. Call unknown contract", expect: "reject",
			fn: func() error {
				return signTx("0x000000000000000000000000000000000000dEaD", "0", "0xdeadbeef")
			},
		},
		{
			name: "5. Personal sign arbitrary message", expect: "reject",
			fn: func() error { return signPersonal("Send me all your money") },
		},
		{
			name: "6. Unknown function on CTF Exchange", expect: "reject",
			fn: func() error {
				return signTx("0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E", "0",
					"0x00f55d9d000000000000000000000000dead000000000000000000000000000000000001")
			},
		},
		{
			name: "7. ETH value transfer to CTF Exchange", expect: "reject",
			fn: func() error {
				return signTx("0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E", "1000000000000000000", "0x")
			},
		},
		{
			name: "8. Phishing Permit typed_data", expect: "reject",
			fn: func() error {
				return signTypedData(&client.TypedData{
					Types: map[string][]client.TypedDataField{
						"EIP712Domain": {{Name: "name", Type: "string"}},
						"Permit":       {{Name: "spender", Type: "address"}, {Name: "value", Type: "uint256"}},
					},
					PrimaryType: "Permit",
					Domain:      client.TypedDataDomain{Name: "FakeToken"},
					Message:     map[string]any{"spender": "0xdead000000000000000000000000000000000001", "value": "999999999999"},
				})
			},
		},

		// --- Legitimate: should be allowed ---
		{
			name: "9. USDC approve to CTF Exchange (legit Polymarket)", expect: "allow",
			fn: func() error {
				return signTx("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "0",
					"0x095ea7b30000000000000000000000004bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982Effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
			},
		},
	}

	fmt.Println("=== Malicious Signing Tests Against Production Service ===")
	fmt.Println()

	passed, failed := 0, 0
	for _, tc := range tests {
		err := tc.fn()
		got := "allow"
		detail := "signed OK"
		if err != nil {
			got = "reject"
			detail = err.Error()
		}

		status := "PASS"
		if (tc.expect == "reject" && got != "reject") || (tc.expect == "allow" && got != "allow") {
			status = "FAIL"
			failed++
		} else {
			passed++
		}

		fmt.Printf("[%s] %s\n  expect=%-6s got=%-6s  %s\n\n", status, tc.name, tc.expect, got, detail)
	}

	fmt.Printf("=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
