package rule

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ExtractAmount extracts the spending amount from a request based on the metering method
func ExtractAmount(metering types.BudgetMetering, req *types.SignRequest, parsed *types.ParsedPayload) (*big.Int, error) {
	switch metering.Method {
	case "count_only":
		return big.NewInt(1), nil
	case "tx_value":
		return extractTxValue(parsed)
	case "calldata_param":
		return extractCalldataParam(metering, parsed)
	case "typed_data_field":
		return extractTypedDataField(metering, parsed)
	default:
		// SECURITY: Unknown metering method should return an error, not zero.
		// Returning zero would effectively bypass budget enforcement.
		return nil, fmt.Errorf("unknown metering method: %s", metering.Method)
	}
}

// extractTxValue extracts the transaction value from parsed payload.
// SECURITY: Returns an error when value is missing to prevent zero-cost budget bypass.
func extractTxValue(parsed *types.ParsedPayload) (*big.Int, error) {
	if parsed == nil || parsed.Value == nil {
		return nil, fmt.Errorf("tx_value metering requires a transaction value but parsed payload is nil or has no value")
	}
	n := new(big.Int)
	if _, ok := n.SetString(*parsed.Value, 10); !ok {
		// Try hex
		if _, ok := n.SetString(strings.TrimPrefix(*parsed.Value, "0x"), 16); !ok {
			return nil, fmt.Errorf("cannot parse value '%s' as number", *parsed.Value)
		}
	}
	return n, nil
}

// extractCalldataParam extracts a parameter from calldata using ABI decoding.
// Uses RawData from ParsedPayload which contains the raw transaction data.
// SECURITY: Returns an error when data is missing to prevent zero-cost budget bypass.
func extractCalldataParam(metering types.BudgetMetering, parsed *types.ParsedPayload) (*big.Int, error) {
	if parsed == nil || len(parsed.RawData) == 0 {
		return nil, fmt.Errorf("calldata_param metering requires raw transaction data but parsed payload is nil or has no data")
	}

	// Calldata format: 4-byte selector + 32-byte parameters
	data := parsed.RawData
	if len(data) < 4 {
		return nil, fmt.Errorf("calldata_param metering requires at least 4 bytes of calldata, got %d", len(data))
	}

	params := data[4:]
	paramOffset := metering.ParamIndex * 32

	if paramOffset+32 > len(params) {
		return nil, fmt.Errorf("calldata too short for param_index %d (need %d bytes, have %d)",
			metering.ParamIndex, paramOffset+32, len(params))
	}

	// Extract 32-byte parameter
	paramBytes := params[paramOffset : paramOffset+32]
	amount := new(big.Int).SetBytes(paramBytes)

	return amount, nil
}

// extractTypedDataField extracts a field from EIP-712 typed data message.
// Uses RawData which may contain the typed data JSON, then navigates by field path.
// SECURITY: Returns an error when data is missing to prevent zero-cost budget bypass.
func extractTypedDataField(metering types.BudgetMetering, parsed *types.ParsedPayload) (*big.Int, error) {
	if parsed == nil || len(parsed.RawData) == 0 {
		return nil, fmt.Errorf("typed_data_field metering requires raw data but parsed payload is nil or has no data")
	}

	fieldPath := metering.FieldPath
	if fieldPath == "" {
		return nil, fmt.Errorf("typed_data_field metering requires field_path but it is empty")
	}

	// Try to parse RawData as JSON (typed data payload)
	var typedData map[string]interface{}
	if err := json.Unmarshal(parsed.RawData, &typedData); err != nil {
		return nil, fmt.Errorf("failed to parse raw data as JSON for typed_data_field: %w", err)
	}

	// Navigate the field path (e.g., "message.amount" or just "amount")
	parts := strings.Split(fieldPath, ".")
	var current interface{} = typedData

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			next, ok := v[part]
			if !ok {
				return nil, fmt.Errorf("field '%s' not found in typed data path '%s'", part, fieldPath)
			}
			current = next
		default:
			return nil, fmt.Errorf("cannot navigate into non-map type at '%s' in path '%s'", part, fieldPath)
		}
	}

	// Convert to big.Int
	return valueToBigInt(current)
}

// valueToBigInt converts various types to *big.Int
func valueToBigInt(v interface{}) (*big.Int, error) {
	switch val := v.(type) {
	case string:
		n := new(big.Int)
		if _, ok := n.SetString(val, 10); !ok {
			// Try hex
			if _, ok := n.SetString(strings.TrimPrefix(val, "0x"), 16); !ok {
				return nil, fmt.Errorf("cannot parse '%s' as number", val)
			}
		}
		return n, nil
	case float64:
		// SECURITY: Use big.Float to avoid precision loss for large values.
		// big.NewInt(int64(val)) loses precision for values > 2^53.
		bf := new(big.Float).SetFloat64(val)
		n, accuracy := bf.Int(nil)
		if accuracy != big.Exact {
			// Not an exact integer — could indicate precision issues
			return nil, fmt.Errorf("float64 value %v is not an exact integer (precision loss risk)", val)
		}
		return n, nil
	case int64:
		return big.NewInt(val), nil
	case json.Number:
		n := new(big.Int)
		if _, ok := n.SetString(val.String(), 10); !ok {
			return nil, fmt.Errorf("cannot parse json.Number '%s' as big.Int", val.String())
		}
		return n, nil
	default:
		return nil, fmt.Errorf("unsupported type %T for budget amount", v)
	}
}

// validateDynamicUnit validates the raw unit string from JS validateBudget return.
// SECURITY (CRITICAL-2): Prevents injection attacks and storage abuse via crafted unit strings.
func validateDynamicUnit(rawUnit string) error {
	if len(rawUnit) > maxUnitLength {
		return fmt.Errorf("unit string too long (%d > %d)", len(rawUnit), maxUnitLength)
	}
	if !validDynamicUnitRe.MatchString(rawUnit) {
		return fmt.Errorf("unit %q does not match allowed pattern (hex address or alphanumeric name)", rawUnit)
	}
	return nil
}

// validateDecimals checks that decimals are within a safe range.
// SECURITY (MEDIUM-5): Reject negative decimals (possible from malicious contracts)
// and excessively large values that could cause overflow in decimal-to-raw conversion.
func validateDecimals(decimals int) error {
	if decimals < 0 {
		return fmt.Errorf("negative decimals (%d) not allowed", decimals)
	}
	if decimals > maxDecimalDigits {
		return fmt.Errorf("decimals %d exceeds maximum %d", decimals, maxDecimalDigits)
	}
	return nil
}
