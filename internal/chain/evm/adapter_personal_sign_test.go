package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recoverPersonalSignAddress is a test helper that verifies a personal_sign
// signature by reconstructing the EIP-191 prefix over `message`, hashing,
// and recovering the public key.
func recoverPersonalSignAddress(t *testing.T, message []byte, signature []byte) common.Address {
	t.Helper()
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message)))
	prefixed := append(prefix, message...)
	digest := crypto.Keccak256Hash(prefixed)
	denorm := ethsig.DenormalizeSignatureV(signature)
	pub, err := crypto.SigToPub(digest.Bytes(), denorm)
	require.NoError(t, err)
	return crypto.PubkeyToAddress(*pub)
}

// Anvil default account #0 — well-known test key with a known address.
const (
	testSignerHex     = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	testSignerAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
)

func newPersonalSignAdapter(t *testing.T) *EVMAdapter {
	t.Helper()
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   testSignerAddress,
				KeyEnvVar: testSignerHex,
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)
	return adapter
}

func TestDecodePersonalSignMessage(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{"plain UTF-8", "hello", "hello"},
		{"empty", "", ""},
		{"0x only", "0x", "0x"},
		{"valid hex of hello", "0x68656c6c6f", "hello"},
		{"hex of SIWE", "0x" + hex.EncodeToString([]byte("Sign in with Ethereum")), "Sign in with Ethereum"},
		{"odd-length hex stays literal", "0x123", "0x123"},
		{"non-hex stays literal", "0xZZZZ", "0xZZZZ"},
		{"uppercase 0X is not detected", "0Xabcd", "0Xabcd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodePersonalSignMessage(tt.in)
			assert.Equal(t, tt.out, got)
		})
	}
}

// TestEVMAdapter_Sign_Personal_HexEncoded reproduces the Polymarket/SIWE
// failure: viem/wagmi-style dApps hex-encode their UTF-8 message before
// calling personal_sign. The wallet MUST sign the decoded bytes, not the
// literal hex string. Verifies the resulting signature recovers to the
// signer's address against the *decoded* message.
func TestEVMAdapter_Sign_Personal_HexEncoded(t *testing.T) {
	adapter := newPersonalSignAdapter(t)

	rawMessage := "example.com wants you to sign in with your Ethereum account:\n" + testSignerAddress + "\n\nSign-in nonce: 12345"
	hexMessage := "0x" + hex.EncodeToString([]byte(rawMessage))

	payload, _ := json.Marshal(EVMSignPayload{Message: hexMessage})
	result, err := adapter.Sign(context.Background(), testSignerAddress, SignTypePersonal, "137", payload)
	require.NoError(t, err)
	require.Len(t, result.Signature, 65)

	recovered := recoverPersonalSignAddress(t, []byte(rawMessage), result.Signature)
	assert.Equal(t, strings.ToLower(testSignerAddress), strings.ToLower(recovered.Hex()),
		"signature must recover to the signer address when message is hex-encoded")
}

// TestEVMAdapter_Sign_Personal_PlainText keeps the legacy behaviour: a
// non-hex UTF-8 message is signed verbatim (back-compat with direct REST
// callers that don't hex-encode).
func TestEVMAdapter_Sign_Personal_PlainText(t *testing.T) {
	adapter := newPersonalSignAdapter(t)

	rawMessage := "Plain UTF-8 message"
	payload, _ := json.Marshal(EVMSignPayload{Message: rawMessage})
	result, err := adapter.Sign(context.Background(), testSignerAddress, SignTypePersonal, "1", payload)
	require.NoError(t, err)

	recovered := recoverPersonalSignAddress(t, []byte(rawMessage), result.Signature)
	assert.Equal(t, strings.ToLower(testSignerAddress), strings.ToLower(recovered.Hex()))
}

// TestEVMAdapter_Sign_Personal_HexAndUTF8_AreEquivalent ensures the two
// canonical encodings of the same message produce the *same* signature —
// this is the MetaMask invariant dApps rely on.
func TestEVMAdapter_Sign_Personal_HexAndUTF8_AreEquivalent(t *testing.T) {
	adapter := newPersonalSignAdapter(t)
	msg := "Hello Polymarket"

	plainPayload, _ := json.Marshal(EVMSignPayload{Message: msg})
	hexPayload, _ := json.Marshal(EVMSignPayload{Message: "0x" + hex.EncodeToString([]byte(msg))})

	plain, err := adapter.Sign(context.Background(), testSignerAddress, SignTypePersonal, "1", plainPayload)
	require.NoError(t, err)
	hexed, err := adapter.Sign(context.Background(), testSignerAddress, SignTypePersonal, "1", hexPayload)
	require.NoError(t, err)

	assert.Equal(t, plain.Signature, hexed.Signature,
		"personal_sign(\"hello\") and personal_sign(hex(\"hello\")) must produce identical signatures")
}
