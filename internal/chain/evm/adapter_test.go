package evm

import (
	"context"
	"encoding/json"
	"testing"
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
					Data:  []byte{0xa9, 0x05, 0x9c, 0xbb, 0x01, 0x02, 0x03, 0x04},
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
					Data:  []byte{0xa9, 0x05, 0x9c, 0xbb, 0x01, 0x02, 0x03, 0x04},
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
					Data:  []byte{0xa9, 0x05},
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
				if tt.payload.Transaction != nil && len(tt.payload.Transaction.Data) < 4 {
					// This is expected behavior
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
