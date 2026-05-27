// Package evm provides the EVM chain implementation including rule evaluation,
// signer management, and transaction processing for the remote-signer daemon.
package evm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// abiEncode uses go-ethereum/abi Arguments.Pack (same as Solidity abi.encode).
func abiEncode(types []string, values []interface{}) ([]byte, error) {
	args, err := typesToArguments(types)
	if err != nil {
		return nil, err
	}
	return args.Pack(values...)
}

// abiDecode uses go-ethereum/abi Arguments.UnpackValues (same as Solidity abi.decode).
func abiDecode(types []string, data []byte) ([]interface{}, error) {
	args, err := typesToArguments(types)
	if err != nil {
		return nil, err
	}
	unpacked, err := args.UnpackValues(data)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(unpacked))
	for _, v := range unpacked {
		out = append(out, abiValueToJS(v))
	}
	return out, nil
}

func typesToArguments(types []string) (abi.Arguments, error) {
	args := make(abi.Arguments, 0, len(types))
	for _, t := range types {
		typ, err := abi.NewType(t, "", nil)
		if err != nil {
			return nil, err
		}
		args = append(args, abi.Argument{Name: "", Type: typ})
	}
	return args, nil
}

// jsValueToAbiArg converts JS value (from Export()) to Go type expected by go-ethereum/abi Pack.
func jsValueToAbiArg(typ string, val interface{}) (interface{}, error) {
	switch typ {
	case "address":
		s, ok := val.(string)
		if !ok || !common.IsHexAddress(s) {
			return nil, fmt.Errorf("address must be a hex address string")
		}
		return common.HexToAddress(s), nil
	case "uint256", "uint8", "uint16", "uint32", "uint64", "uint":
		return toBigIntOrUint(val, typ)
	case "int256", "int8", "int16", "int32", "int64", "int":
		return toBigIntOrInt(val, typ)
	case "bool":
		b, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("bool expected, got %T", val)
		}
		return b, nil
	case "bytes32":
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("bytes32 must be a hex string")
		}
		s = strings.TrimPrefix(s, "0x")
		if len(s) != 64 {
			return nil, fmt.Errorf("bytes32 must be 32 bytes (64 hex chars)")
		}
		return common.HexToHash("0x" + s), nil
	case "bytes", "string":
		if s, ok := val.(string); ok {
			if typ == "bytes" && strings.HasPrefix(s, "0x") {
				b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
				if err != nil {
					return nil, fmt.Errorf("bytes: invalid hex: %w", err)
				}
				return b, nil
			}
			return s, nil
		}
		return nil, fmt.Errorf("%s must be a string", typ)
	default:
		return nil, fmt.Errorf("unsupported abi type %s", typ)
	}
}

func toBigIntOrUint(val interface{}, typ string) (interface{}, error) {
	var b big.Int
	switch v := val.(type) {
	case string:
		if _, ok := b.SetString(v, 10); !ok {
			return nil, fmt.Errorf("invalid decimal string %q for %s", v, typ)
		}
	case float64:
		b.SetInt64(int64(v))
	default:
		return nil, fmt.Errorf("expected string or number for %s, got %T", typ, val)
	}
	switch typ {
	case "uint8":
		if b.IsUint64() && b.Uint64() <= 0xff {
			return byte(b.Uint64()), nil // #nosec G115 -- bounds checked above
		}
		return nil, fmt.Errorf("value %s overflows uint8", b.String())
	case "uint16":
		if b.IsUint64() && b.Uint64() <= 0xffff {
			return uint16(b.Uint64()), nil // #nosec G115 -- bounds checked above
		}
		return nil, fmt.Errorf("value %s overflows uint16", b.String())
	case "uint32":
		if b.IsUint64() && b.Uint64() <= 0xffffffff {
			return uint32(b.Uint64()), nil // #nosec G115 -- bounds checked above
		}
		return nil, fmt.Errorf("value %s overflows uint32", b.String())
	case "uint64":
		if b.IsUint64() {
			return b.Uint64(), nil
		}
		return nil, fmt.Errorf("value %s overflows uint64", b.String())
	default:
		return &b, nil
	}
}

func toBigIntOrInt(val interface{}, typ string) (interface{}, error) {
	var b big.Int
	switch v := val.(type) {
	case string:
		if _, ok := b.SetString(v, 10); !ok {
			return nil, fmt.Errorf("invalid decimal string %q for %s", v, typ)
		}
	case float64:
		b.SetInt64(int64(v))
	default:
		return nil, fmt.Errorf("expected string or number for %s, got %T", typ, val)
	}
	switch typ {
	case "int8", "int16", "int32", "int64":
		i64 := b.Int64()
		return i64, nil
	default:
		return &b, nil
	}
}

// abiValueToJS converts go-ethereum/abi UnpackValues result to JS-exportable (Solidity semantics).
// Tuple (struct) is converted to map with original ABI field names.
func abiValueToJS(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case common.Address:
		return val.Hex()
	case common.Hash:
		return val.Hex()
	case *big.Int:
		return val.String()
	case byte:
		return fmt.Sprintf("%d", val)
	case uint16:
		return fmt.Sprintf("%d", val)
	case uint32:
		return fmt.Sprintf("%d", val)
	case uint64:
		return fmt.Sprintf("%d", val)
	case int8, int16, int32, int64:
		return fmt.Sprintf("%d", val)
	case []byte:
		return "0x" + hex.EncodeToString(val)
	case bool:
		return val
	case string:
		return val
	default:
		if reflect.TypeOf(v).Kind() == reflect.Struct {
			return abiStructToMap(v)
		}
		return v
	}
}
