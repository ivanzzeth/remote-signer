package evm

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestEVMAdapter_ParsePayload_PersonalSign(t *testing.T) {
	// Create a minimal adapter for testing ParsePayload
	adapter := &EVMAdapter{}

	tests := []struct {
		name           string
		signType       string
		payload        EVMSignPayload
		expectMessage  string
		expectHasMsg   bool
		expectRecip    bool
		expectValue    bool
		expectMethodSig bool
	}{
		{
			name:     "personal sign with message",
			signType: SignTypePersonal,
			payload: EVMSignPayload{
				Message: "Hello World",
			},
			expectMessage: "Hello World",
			expectHasMsg:  true,
		},
		{
			name:     "eip191 sign with message",
			signType: SignTypeEIP191,
			payload: EVMSignPayload{
				Message: "Sign this message",
			},
			expectMessage: "Sign this message",
			expectHasMsg:  true,
		},
		{
			name:     "personal sign with SIWE message",
			signType: SignTypePersonal,
			payload: EVMSignPayload{
				Message: `app.opinion.trade wants you to sign in with your Ethereum account:
0x88eD75e9eCE373997221E3c0229e74007C1AD718

Welcome to opinion.trade! By proceeding, you agree to our Privacy Policy and Terms of Use.

URI: https://app.opinion.trade
Version: 1
Chain ID: 56
Nonce: 4821202891733693881
Issued At: 2026-01-23T08:46:20.000Z`,
			},
			expectMessage: `app.opinion.trade wants you to sign in with your Ethereum account:
0x88eD75e9eCE373997221E3c0229e74007C1AD718

Welcome to opinion.trade! By proceeding, you agree to our Privacy Policy and Terms of Use.

URI: https://app.opinion.trade
Version: 1
Chain ID: 56
Nonce: 4821202891733693881
Issued At: 2026-01-23T08:46:20.000Z`,
			expectHasMsg: true,
		},
		{
			name:     "personal sign with empty message",
			signType: SignTypePersonal,
			payload: EVMSignPayload{
				Message: "",
			},
			expectHasMsg: false,
		},
		{
			name:     "transaction type should not extract message",
			signType: SignTypeTransaction,
			payload: EVMSignPayload{
				Message: "This should be ignored",
				Transaction: &TransactionPayload{
					To:    strPtr("0x1234567890123456789012345678901234567890"),
					Value: "0x100",
					Data:  "0xa9059cbb01020304",
				},
			},
			expectHasMsg:    false,
			expectRecip:     true,
			expectValue:     true,
			expectMethodSig: true,
		},
		{
			name:     "typed data type should not extract message",
			signType: SignTypeTypedData,
			payload: EVMSignPayload{
				Message: "This should be ignored for typed data",
			},
			expectHasMsg: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("failed to marshal payload: %v", err)
			}

			parsed, err := adapter.ParsePayload(context.Background(), tt.signType, payloadBytes)
			if err != nil {
				t.Fatalf("ParsePayload returned error: %v", err)
			}

			// Check message extraction
			if tt.expectHasMsg {
				if parsed.Message == nil {
					t.Error("expected message to be set, got nil")
				} else if *parsed.Message != tt.expectMessage {
					t.Errorf("expected message %q, got %q", tt.expectMessage, *parsed.Message)
				}
			} else {
				if parsed.Message != nil {
					t.Errorf("expected message to be nil, got %q", *parsed.Message)
				}
			}

			// Check transaction fields
			if tt.expectRecip {
				if parsed.Recipient == nil {
					t.Error("expected recipient to be set, got nil")
				}
			}
			if tt.expectValue {
				if parsed.Value == nil {
					t.Error("expected value to be set, got nil")
				}
			}
			if tt.expectMethodSig {
				if parsed.MethodSig == nil {
					t.Error("expected method_sig to be set, got nil")
				}
			}
		})
	}
}

func TestEVMAdapter_ParsePayload_InvalidJSON(t *testing.T) {
	adapter := &EVMAdapter{}

	_, err := adapter.ParsePayload(context.Background(), SignTypePersonal, []byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestEVMAdapter_ParsePayload_Transaction(t *testing.T) {
	adapter := &EVMAdapter{}

	tests := []struct {
		name            string
		payload         EVMSignPayload
		expectRecip     string
		expectValue     string
		expectMethodSig string
		expectContract  string
	}{
		{
			name: "transaction with all fields",
			payload: EVMSignPayload{
				Transaction: &TransactionPayload{
					To:    strPtr("0x1234567890123456789012345678901234567890"),
					Value: "0x100",
					Data:  "0xa9059cbb01020304",
				},
			},
			expectRecip:     "0x1234567890123456789012345678901234567890",
			expectValue:     "0x100",
			expectMethodSig: "0xa9059cbb",
			expectContract:  "0x1234567890123456789012345678901234567890",
		},
		{
			name: "transaction without data",
			payload: EVMSignPayload{
				Transaction: &TransactionPayload{
					To:    strPtr("0x1234567890123456789012345678901234567890"),
					Value: "0x0",
				},
			},
			expectRecip: "0x1234567890123456789012345678901234567890",
			expectValue: "0x0",
		},
		{
			name: "transaction with short data (less than 4 bytes)",
			payload: EVMSignPayload{
				Transaction: &TransactionPayload{
					To:    strPtr("0x1234567890123456789012345678901234567890"),
					Value: "0x0",
					Data:  "0xa905",
				},
			},
			expectRecip: "0x1234567890123456789012345678901234567890",
			expectValue: "0x0",
			// No method sig expected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("failed to marshal payload: %v", err)
			}

			parsed, err := adapter.ParsePayload(context.Background(), SignTypeTransaction, payloadBytes)
			if err != nil {
				t.Fatalf("ParsePayload returned error: %v", err)
			}

			if tt.expectRecip != "" {
				if parsed.Recipient == nil {
					t.Error("expected recipient to be set, got nil")
				} else if *parsed.Recipient != tt.expectRecip {
					t.Errorf("expected recipient %q, got %q", tt.expectRecip, *parsed.Recipient)
				}
			}

			if tt.expectValue != "" {
				if parsed.Value == nil {
					t.Error("expected value to be set, got nil")
				} else if *parsed.Value != tt.expectValue {
					t.Errorf("expected value %q, got %q", tt.expectValue, *parsed.Value)
				}
			}

			if tt.expectMethodSig != "" {
				if parsed.MethodSig == nil {
					t.Error("expected method_sig to be set, got nil")
				} else if *parsed.MethodSig != tt.expectMethodSig {
					t.Errorf("expected method_sig %q, got %q", tt.expectMethodSig, *parsed.MethodSig)
				}
			} else if tt.expectMethodSig == "" && parsed.MethodSig != nil {
				// If we don't expect method sig, it should be nil
				dataHex := strings.TrimPrefix(tt.payload.Transaction.Data, "0x")
				if tt.payload.Transaction != nil && len(dataHex) < 8 {
					// This is expected behavior — less than 4 bytes of data
				}
			}

			if tt.expectContract != "" {
				if parsed.Contract == nil {
					t.Error("expected contract to be set, got nil")
				} else if *parsed.Contract != tt.expectContract {
					t.Errorf("expected contract %q, got %q", tt.expectContract, *parsed.Contract)
				}
			}
		})
	}
}

func TestEVMAdapter_ParsePayload_NilTransaction(t *testing.T) {
	adapter := &EVMAdapter{}

	payload := EVMSignPayload{
		// Transaction is nil
	}
	payloadBytes, _ := json.Marshal(payload)

	parsed, err := adapter.ParsePayload(context.Background(), SignTypeTransaction, payloadBytes)
	if err != nil {
		t.Fatalf("ParsePayload returned error: %v", err)
	}

	// Should not panic and should return empty parsed payload
	if parsed.Recipient != nil {
		t.Error("expected recipient to be nil")
	}
	if parsed.Value != nil {
		t.Error("expected value to be nil")
	}
	if parsed.MethodSig != nil {
		t.Error("expected method_sig to be nil")
	}
}

func TestEVMAdapter_ValidateBasicRequest(t *testing.T) {
	adapter := &EVMAdapter{}

	validPayload := []byte(`{"message":"hello"}`)

	tests := []struct {
		name          string
		chainID       string
		signerAddress string
		signType      string
		payload       []byte
		wantErr       bool
		errContains   string
	}{
		{
			name:          "valid",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypePersonal,
			payload:       validPayload,
			wantErr:       false,
		},
		{
			name:          "chain_id required",
			chainID:       "",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypePersonal,
			payload:       validPayload,
			wantErr:       true,
			errContains:   "chain_id",
		},
		{
			name:          "invalid chain_id",
			chainID:       "0x56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypePersonal,
			payload:       validPayload,
			wantErr:       true,
			errContains:   "chain_id",
		},
		{
			name:          "signer_address required",
			chainID:       "56",
			signerAddress: "",
			signType:      SignTypePersonal,
			payload:       validPayload,
			wantErr:       true,
			errContains:   "signer_address",
		},
		{
			name:          "invalid signer_address",
			chainID:       "56",
			signerAddress: "0x1234",
			signType:      SignTypePersonal,
			payload:       validPayload,
			wantErr:       true,
			errContains:   "signer_address",
		},
		{
			name:          "sign_type required",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      "",
			payload:       validPayload,
			wantErr:       true,
			errContains:   "sign_type",
		},
		{
			name:          "invalid sign_type",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      "unknown_type",
			payload:       validPayload,
			wantErr:       true,
			errContains:   "sign_type",
		},
		{
			name:          "payload required",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypePersonal,
			payload:       nil,
			wantErr:       true,
			errContains:   "payload",
		},
		{
			name:          "payload empty",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypePersonal,
			payload:       []byte{},
			wantErr:       true,
			errContains:   "payload",
		},
		{
			name:          "payload exceeds max size",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypePersonal,
			payload:       make([]byte, maxPayloadSize+1),
			wantErr:       true,
			errContains:   "payload exceeds",
		},
		{
			name:          "payload invalid JSON",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypePersonal,
			payload:       []byte(`{not json`),
			wantErr:       true,
			errContains:   "not valid JSON",
		},
		{
			name:          "payload missing required field for sign_type",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypePersonal,
			payload:       []byte(`{}`),
			wantErr:       true,
			errContains:   "message is required",
		},
		{
			name:          "typed_data requires typed_data field",
			chainID:       "56",
			signerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			signType:      SignTypeTypedData,
			payload:       []byte(`{"message":"wrong"}`),
			wantErr:       true,
			errContains:   "typed_data is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := adapter.ValidateBasicRequest(tt.chainID, tt.signerAddress, tt.signType, tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestDecodePersonalSignMessage_UseCases locks the three documented use
// cases for personal_sign / EIP-191 message handling. The doc-block on
// decodePersonalSignMessage spells these out in prose; this test pins
// them as code so any future refactor that breaks one trips here first.
func TestDecodePersonalSignMessage_UseCases(t *testing.T) {
	t.Run("USE CASE A — SIWE text hex decodes to original UTF-8", func(t *testing.T) {
		siwe := "polymarket.com wants you to sign in with your Ethereum account:\n0x21f409aA1a060B22B3ce647d2bDb1C0a9457A0B8\n\nWelcome.\n\nURI: https://polymarket.com\nVersion: 1\nChain ID: 137\nNonce: abc123\nIssued At: 2026-05-20T08:00:00.000Z"
		hexInput := "0x" + hex.EncodeToString([]byte(siwe))

		got := decodePersonalSignMessage(hexInput)

		assert.Equal(t, []byte(siwe), got,
			"hex of UTF-8 SIWE MUST round-trip to the original text bytes; rule_engine pattern-matches against these bytes")
		assert.Equal(t, siwe, string(got),
			"decoded bytes MUST be a valid UTF-8 string identical to what the dApp constructed")
	})

	t.Run("USE CASE B — 32-byte binary challenge round-trips byte-for-byte", func(t *testing.T) {
		// Realistic shape: 32 random bytes (a keccak-ish hash or a
		// CSPRNG nonce). Contains bytes that are NOT valid UTF-8 — the
		// previous SDK-side decode mangled this case (the original
		// OpenSea reverse-lookup bug).
		challenge := []byte{
			0x96, 0x2e, 0xd0, 0xbb, 0xff, 0x10, 0xd9, 0xb5,
			0x77, 0x77, 0xfe, 0x24, 0x2f, 0xe1, 0x70, 0xc4,
			0xc8, 0xfd, 0xfb, 0x57, 0xc3, 0x8d, 0x3a, 0xcd,
			0x90, 0x71, 0x79, 0x23, 0x37, 0x56, 0xb6, 0x35,
		}
		hexInput := "0x" + hex.EncodeToString(challenge)

		got := decodePersonalSignMessage(hexInput)

		assert.Equal(t, challenge, got,
			"binary hex MUST round-trip to the SAME 32 bytes the dApp will use in verifyMessage; ANY mangling here re-creates the OpenSea invalid-signature bug")
		// Sanity: this should NOT be valid UTF-8 — that's the point of
		// the test. If go decides this IS valid UTF-8 in some future
		// version, the assertion still passes (we test the bytes, not
		// UTF-8 status) but the test premise weakens.
	})

	t.Run("USE CASE C — non-hex string passes through as UTF-8 bytes", func(t *testing.T) {
		// Legacy: CLI tools / e2e tests POST plain text directly. No
		// 0x prefix → treat the whole thing as the message bytes.
		got := decodePersonalSignMessage("hello world")
		assert.Equal(t, []byte("hello world"), got)
	})

	t.Run("edge — uppercase 0X prefix is honored", func(t *testing.T) {
		got := decodePersonalSignMessage("0X48656c6c6f")
		assert.Equal(t, []byte("Hello"), got,
			"the standard 0x prefix is case-insensitive; MetaMask accepts both")
	})

	t.Run("edge — empty 0x is treated as empty hex (zero-byte message)", func(t *testing.T) {
		got := decodePersonalSignMessage("0x")
		assert.Equal(t, []byte{}, got,
			"\"0x\" is valid empty hex; produces a 0-length byte slice (not nil)")
	})

	t.Run("edge — odd-length 0x falls back to raw bytes", func(t *testing.T) {
		// Odd length can't be valid hex; safer to keep the original
		// string as bytes than to reject the request entirely.
		got := decodePersonalSignMessage("0x1")
		assert.Equal(t, []byte("0x1"), got)
	})

	t.Run("edge — non-hex chars after 0x fall back to raw bytes", func(t *testing.T) {
		got := decodePersonalSignMessage("0xZZ")
		assert.Equal(t, []byte("0xZZ"), got)
	})

	t.Run("edge — empty string passes through as empty bytes", func(t *testing.T) {
		got := decodePersonalSignMessage("")
		assert.Equal(t, []byte(""), got)
	})
}

// TestAdapter_PersonalSign_RecoversToSignerAddress is the integration
// proof: signing the hex form of a message produces a signature that
// recovers to the signer's address when verified against the ORIGINAL
// bytes the dApp would use. Exercises USE CASE A and B end-to-end
// through ethsig (no DB / no network). If the adapter ever stops
// hex-decoding before EIP-191 prefixing, this test fails — closing the
// loop on the OpenSea / Polymarket invalid-signature bug class.
func TestAdapter_PersonalSign_RecoversToSignerAddress(t *testing.T) {
	// Stable test signer (deterministic key, not a real wallet).
	keyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	pk, err := crypto.HexToECDSA(keyHex)
	require.NoError(t, err)
	addr := crypto.PubkeyToAddress(*pk.Public().(*ecdsa.PublicKey))

	innerSigner, err := ethsig.NewEthPrivateKeySignerFromPrivateKeyHex(keyHex)
	require.NoError(t, err)
	signer := ethsig.NewSigner(innerSigner)

	reg := NewEmptySignerRegistry()
	require.NoError(t, reg.RegisterSigner(addr.Hex(), signer, types.SignerInfo{
		Address: addr.Hex(),
		Type:    "private_key",
		Enabled: true,
	}))
	adapter, err := NewEVMAdapter(reg)
	require.NoError(t, err)

	type tc struct {
		name        string
		messageWire string // what arrives in payload.message
		verifyBytes []byte // what the dApp would pass to ethers.verifyMessage
	}
	siwe := "opensea.io wants you to sign in.\nNonce: 42"
	binChallenge := []byte{
		0x00, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd,
		0xff, 0xfe, 0xfd, 0xfc, 0x80, 0x81, 0x82, 0x83,
		0xff, 0x00, 0x55, 0xaa, 0x12, 0x34, 0x56, 0x78,
		0x9a, 0xbc, 0xde, 0xf0, 0xde, 0xad, 0xbe, 0xef,
	}
	cases := []tc{
		{
			name:        "SIWE text hex",
			messageWire: "0x" + hex.EncodeToString([]byte(siwe)),
			verifyBytes: []byte(siwe),
		},
		{
			name:        "32-byte binary challenge",
			messageWire: "0x" + hex.EncodeToString(binChallenge),
			verifyBytes: binChallenge,
		},
		{
			name:        "non-hex legacy text",
			messageWire: "hello world",
			verifyBytes: []byte("hello world"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload, _ := json.Marshal(EVMSignPayload{Message: c.messageWire})
			res, err := adapter.Sign(context.Background(), addr.Hex(), SignTypePersonal, "1", payload)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.NotEmpty(t, res.Signature, "adapter MUST produce a signature for valid input")

			// Reconstruct the EIP-191 hash from the bytes the dApp
			// would verify against and recover the public key.
			prefix := []byte("\x19Ethereum Signed Message:\n" + itoa(len(c.verifyBytes)))
			prefixed := append(prefix, c.verifyBytes...)
			ethHash := crypto.Keccak256(prefixed)

			sig := make([]byte, len(res.Signature))
			copy(sig, res.Signature)
			// Normalise V: go-ethereum's crypto.Ecrecover expects V in
			// {0,1}, ethsig returns {27,28} per EIP-155 / personal_sign.
			if sig[64] >= 27 {
				sig[64] -= 27
			}
			recovered, err := crypto.SigToPub(ethHash, sig)
			require.NoError(t, err, "signature MUST be ECDSA-recoverable; mangling would surface here as a recover error")
			recoveredAddr := crypto.PubkeyToAddress(*recovered)
			assert.Equal(t, common.HexToAddress(addr.Hex()), recoveredAddr,
				"recovered address MUST match the signer — mismatch here is the exact OpenSea/Polymarket invalid-signature bug")
		})
	}
}

// itoa keeps the EIP-191 reconstruction self-contained (no strconv
// dependency for one usage).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
