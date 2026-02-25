package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// DelegatePayloadToSignRequest converts a delegation payload (RuleInput-shaped map or *RuleInput)
// into SignRequest and ParsedPayload for evaluating the target rule.
// Used by the rule engine when resolving evm_js delegation. Implements the signature expected
// by rule.WithDelegationPayloadConverter. mode is "single" or "per_item"; for "single" payload
// is one RuleInput; for "per_item" this is called per element.
func DelegatePayloadToSignRequest(ctx context.Context, payload interface{}, _ string) (*types.SignRequest, *types.ParsedPayload, error) {
	if payload == nil {
		return nil, nil, fmt.Errorf("delegation payload is nil")
	}
	var m map[string]interface{}
	switch v := payload.(type) {
	case map[string]interface{}:
		m = v
	case *RuleInput:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, nil, err
		}
	default:
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, nil, err
		}
	}
	return ruleInputMapToSignRequest(m)
}

func ruleInputMapToSignRequest(m map[string]interface{}) (*types.SignRequest, *types.ParsedPayload, error) {
	chainID, _ := m["chain_id"].(float64)
	signer, _ := m["signer"].(string)
	signType, _ := m["sign_type"].(string)
	if signer == "" {
		return nil, nil, fmt.Errorf("delegation payload missing signer")
	}
	signTypeEVM := mapRuleInputSignTypeToEVM(signType)
	payloadBytes, err := buildEVMPayloadFromRuleInputMap(m)
	if err != nil {
		return nil, nil, err
	}
	req := &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		ChainID:       strconv.FormatInt(int64(chainID), 10),
		SignerAddress: signer,
		SignType:      signTypeEVM,
		Payload:       payloadBytes,
	}
	parsed := parsedPayloadFromRuleInputMap(m)
	return req, parsed, nil
}

func mapRuleInputSignTypeToEVM(s string) string {
	switch s {
	case "transaction":
		return SignTypeTransaction
	case "typed_data":
		return SignTypeTypedData
	case "personal_sign":
		return SignTypePersonal
	default:
		return s
	}
}

func buildEVMPayloadFromRuleInputMap(m map[string]interface{}) ([]byte, error) {
	signType, _ := m["sign_type"].(string)
	payload := make(map[string]interface{})
	switch signType {
	case "transaction":
		if tx, ok := m["transaction"].(map[string]interface{}); ok {
			to, _ := tx["to"].(string)
			valueHex, _ := tx["value"].(string)
			valueDec := hexWeiToDecimal(valueHex)
			payload["transaction"] = map[string]interface{}{
				"to":       to,
				"value":    valueDec,
				"data":     firstStr(tx["data"], "0x"),
				"gas":      uint64(21000),
				"gasPrice": "0",
				"txType":   "legacy",
			}
		}
	case "typed_data":
		if td, ok := m["typed_data"].(map[string]interface{}); ok {
			payload["typed_data"] = td
		}
	case "personal_sign":
		if ps, ok := m["personal_sign"].(map[string]interface{}); ok {
			if msg, ok := ps["message"].(string); ok {
				payload["message"] = msg
			}
		}
	}
	return json.Marshal(payload)
}

func firstStr(v interface{}, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func hexWeiToDecimal(hexStr string) string {
	if hexStr == "" || hexStr == "0x0" || hexStr == "0x" {
		return "0"
	}
	hexStr = strings.TrimPrefix(strings.TrimPrefix(hexStr, "0x"), "0X")
	var b big.Int
	if _, ok := b.SetString(hexStr, 16); !ok {
		return "0"
	}
	return b.String()
}

func parsedPayloadFromRuleInputMap(m map[string]interface{}) *types.ParsedPayload {
	parsed := &types.ParsedPayload{}
	if tx, ok := m["transaction"].(map[string]interface{}); ok {
		if to, ok := tx["to"].(string); ok && to != "" {
			parsed.Recipient = &to
		}
		if v, ok := tx["value"].(string); ok {
			parsed.Value = strPtrDeleg(hexWeiToDecimal(v))
		}
		if mid, ok := tx["methodId"].(string); ok {
			parsed.MethodSig = &mid
			parsed.Contract = parsed.Recipient
		}
	}
	if ps, ok := m["personal_sign"].(map[string]interface{}); ok {
		if msg, ok := ps["message"].(string); ok {
			parsed.Message = &msg
		}
	}
	return parsed
}

func strPtrDeleg(s string) *string { return &s }
