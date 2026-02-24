package evm

import (
	"context"
	"encoding/json"
	"strings"
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
