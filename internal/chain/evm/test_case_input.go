package evm

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestCaseInputToSignRequest converts a test case input map (from YAML/JSON test_cases)
// to a SignRequest and ParsedPayload suitable for engine evaluation.
// The input map uses the same shape as RuleInput: sign_type, chain_id, signer,
// transaction (to/value/data), typed_data, personal_sign.
func TestCaseInputToSignRequest(input map[string]interface{}) (*types.SignRequest, *types.ParsedPayload, error) {
	if input == nil {
		return nil, nil, fmt.Errorf("input is nil")
	}

	// Extract common fields
	signType := stringFromMap(input, "sign_type")
	chainID := stringFromMap(input, "chain_id")
	signer := stringFromMap(input, "signer")

	if chainID == "" {
		chainID = "1"
	}
	if signType == "" {
		signType = SignTypeTransaction
	}

	req := &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		ChainID:       chainID,
		SignerAddress:  signer,
		SignType:       signType,
	}
	parsed := &types.ParsedPayload{}

	switch signType {
	case SignTypeTransaction, "":
		// Build transaction payload from input
		txMap, ok := input["transaction"]
		if ok {
			txData, err := json.Marshal(txMap)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid transaction in test input: %w", err)
			}
			var tx TransactionPayload
			if err := json.Unmarshal(txData, &tx); err != nil {
				return nil, nil, fmt.Errorf("invalid transaction payload: %w", err)
			}
			payload := EVMSignPayload{Transaction: &tx}
			payloadJSON, _ := json.Marshal(payload)
			req.Payload = payloadJSON

			if tx.To != nil {
				parsed.Recipient = tx.To
			}
			if tx.Value != "" {
				parsed.Value = &tx.Value
			}
			if tx.Data != "" {
				data := strings.TrimPrefix(tx.Data, "0x")
				if len(data) >= 8 {
					sel := "0x" + data[:8]
					parsed.MethodSig = &sel
				}
				rawData, err := hex.DecodeString(data)
				if err == nil {
					parsed.RawData = rawData
				}
			}
		}

	case SignTypeTypedData:
		// Build typed data payload from input
		tdMap, ok := input["typed_data"]
		if ok {
			tdData, err := json.Marshal(tdMap)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid typed_data in test input: %w", err)
			}
			var td TypedDataPayload
			if err := json.Unmarshal(tdData, &td); err != nil {
				return nil, nil, fmt.Errorf("invalid typed_data payload: %w", err)
			}
			payload := EVMSignPayload{TypedData: &td}
			payloadJSON, _ := json.Marshal(payload)
			req.Payload = payloadJSON
		}

	case SignTypePersonal, SignTypeEIP191:
		// Build personal sign payload from input
		msg := stringFromMap(input, "message")
		if msg == "" {
			if ps, ok := input["personal_sign"]; ok {
				if psMap, ok := ps.(map[string]interface{}); ok {
					msg = stringFromMap(psMap, "message")
				}
			}
		}
		if msg != "" {
			payload := EVMSignPayload{Message: msg}
			payloadJSON, _ := json.Marshal(payload)
			req.Payload = payloadJSON
			parsed.Message = &msg
		}
	}

	return req, parsed, nil
}

// stringFromMap extracts a string value from a map, converting numeric types as needed.
func stringFromMap(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		// JSON numbers are float64; convert to int string if whole number
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%v", val)
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
