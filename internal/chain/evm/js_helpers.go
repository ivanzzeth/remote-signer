package evm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grafana/sobek"
)

// injectHelpers injects rule-engine globals: fail(reason), ok(), eq, keccak256, selector, toChecksum,
// isAddress, toWei, fromWei, and abi.encode / abi.decode (via go-ethereum/accounts/abi, Solidity-aligned).
// Rules must not check for presence; the engine guarantees they exist.
func injectHelpers(vm *sobek.Runtime) error {
	if err := vm.Set("fail", vm.ToValue(func(call sobek.FunctionCall) sobek.Value {
		reason := ""
		if len(call.Arguments) > 0 && call.Argument(0) != nil && !call.Argument(0).Equals(sobek.Undefined()) {
			reason = call.Argument(0).String()
		}
		return vm.ToValue(map[string]interface{}{"valid": false, "reason": reason})
	})); err != nil {
		return err
	}
	if err := vm.Set("ok", vm.ToValue(func(call sobek.FunctionCall) sobek.Value {
		return vm.ToValue(map[string]interface{}{"valid": true})
	})); err != nil {
		return err
	}

	set := func(name string, fn func(sobek.FunctionCall) sobek.Value) error {
		return vm.Set(name, vm.ToValue(fn))
	}

	if err := set("eq", func(call sobek.FunctionCall) sobek.Value {
		a := call.Argument(0).Export()
		b := call.Argument(1).Export()
		return vm.ToValue(reflect.DeepEqual(a, b))
	}); err != nil {
		return err
	}
	if err := set("keccak256", func(call sobek.FunctionCall) sobek.Value {
		s := call.Argument(0).String()
		var data []byte
		if strings.HasPrefix(s, "0x") {
			var err error
			data, err = hex.DecodeString(strings.TrimPrefix(s, "0x"))
			if err != nil {
				return vm.ToValue(nil)
			}
		} else {
			data = []byte(s)
		}
		hash := common.BytesToHash(crypto.Keccak256(data))
		return vm.ToValue(hash.Hex())
	}); err != nil {
		return err
	}
	if err := set("selector", func(call sobek.FunctionCall) sobek.Value {
		sig := call.Argument(0).String()
		h := crypto.Keccak256([]byte(sig))
		if len(h) < 4 {
			return vm.ToValue("0x")
		}
		return vm.ToValue("0x" + hex.EncodeToString(h[:4]))
	}); err != nil {
		return err
	}
	if err := set("toChecksum", func(call sobek.FunctionCall) sobek.Value {
		addr := call.Argument(0).String()
		return vm.ToValue(common.HexToAddress(addr).Hex())
	}); err != nil {
		return err
	}
	if err := set("isAddress", func(call sobek.FunctionCall) sobek.Value {
		addr := call.Argument(0).String()
		return vm.ToValue(common.IsHexAddress(addr))
	}); err != nil {
		return err
	}
	if err := set("toWei", func(call sobek.FunctionCall) sobek.Value {
		eth := call.Argument(0).String()
		var b big.Int
		if _, ok := b.SetString(eth, 10); !ok {
			return vm.ToValue("0")
		}
		var mul big.Int
		mul.Exp(big.NewInt(10), big.NewInt(18), nil)
		b.Mul(&b, &mul)
		return vm.ToValue(b.String())
	}); err != nil {
		return err
	}
	if err := set("fromWei", func(call sobek.FunctionCall) sobek.Value {
		wei := call.Argument(0).String()
		var b big.Int
		if _, ok := b.SetString(wei, 10); !ok {
			return vm.ToValue("0")
		}
		var div big.Int
		div.Exp(big.NewInt(10), big.NewInt(18), nil)
		b.Div(&b, &div)
		return vm.ToValue(b.String())
	}); err != nil {
		return err
	}

	// abi: Solidity-aligned. abi.encode(types[], values[]) and abi.decode(data, types[]). Supports tuple (struct).
	// Uses go-ethereum/accounts/abi for ABI spec compliance.
	abiObj := vm.NewObject()
	if err := abiObj.Set("encode", vm.ToValue(func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue("0x")
		}
		typesSpecs, ok := exportTypesSpecs(call.Argument(0))
		if !ok {
			return vm.ToValue("0x")
		}
		valuesExport := call.Argument(1).Export()
		valuesSlice, ok := valuesExport.([]interface{})
		if !ok || len(typesSpecs) != len(valuesSlice) {
			return vm.ToValue("0x")
		}
		args, err := typesToArgumentsFromSpecs(typesSpecs)
		if err != nil {
			return vm.ToValue("0x")
		}
		goValues := make([]interface{}, 0, len(args))
		for i := range args {
			goVal, err := convertValueForPack(args[i].Type, valuesSlice[i])
			if err != nil {
				return vm.ToValue("0x")
			}
			goValues = append(goValues, goVal)
		}
		out, err := args.Pack(goValues...)
		if err != nil {
			return vm.ToValue("0x")
		}
		return vm.ToValue("0x" + hex.EncodeToString(out))
	})); err != nil {
		return err
	}
	if err := abiObj.Set("decode", vm.ToValue(func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue([]interface{}{})
		}
		dataHex := call.Argument(0).String()
		raw := strings.TrimPrefix(strings.TrimPrefix(dataHex, "0x"), "0X")
		data, err := hex.DecodeString(raw)
		if err != nil {
			return vm.ToValue([]interface{}{})
		}
		typesSpecs, ok := exportTypesSpecs(call.Argument(1))
		if !ok {
			return vm.ToValue([]interface{}{})
		}
		args, err := typesToArgumentsFromSpecs(typesSpecs)
		if err != nil {
			return vm.ToValue([]interface{}{})
		}
		unpacked, err := args.UnpackValues(data)
		if err != nil {
			return vm.ToValue([]interface{}{})
		}
		out := make([]interface{}, 0, len(unpacked))
		for _, v := range unpacked {
			out = append(out, abiValueToJS(v))
		}
		return vm.ToValue(out)
	})); err != nil {
		return err
	}
	return vm.Set("abi", abiObj)
}

func exportStringSlice(v sobek.Value) ([]string, bool) {
	if v == nil || v.Equals(sobek.Undefined()) {
		return nil, false
	}
	ex := v.Export()
	sl, ok := ex.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(sl))
	for _, e := range sl {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

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
			return common.Address{}, nil
		}
		return common.HexToAddress(s), nil
	case "uint256", "uint8", "uint16", "uint32", "uint64", "uint":
		return toBigIntOrUint(val, typ)
	case "int256", "int8", "int16", "int32", "int64", "int":
		return toBigIntOrInt(val, typ)
	case "bool":
		b, _ := val.(bool)
		return b, nil
	case "bytes32":
		s, ok := val.(string)
		if !ok {
			return common.Hash{}, nil
		}
		s = strings.TrimPrefix(s, "0x")
		if len(s) != 64 {
			return common.Hash{}, nil
		}
		return common.HexToHash("0x" + s), nil
	case "bytes", "string":
		// dynamic types: pass through; Pack expects []byte or string
		if s, ok := val.(string); ok {
			if typ == "bytes" && strings.HasPrefix(s, "0x") {
				b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
				return b, nil
			}
			return s, nil
		}
		return nil, fmt.Errorf("unsupported value for %s", typ)
	default:
		return nil, fmt.Errorf("unsupported abi type %s", typ)
	}
}

func toBigIntOrUint(val interface{}, typ string) (interface{}, error) {
	var b big.Int
	switch v := val.(type) {
	case string:
		if _, ok := b.SetString(v, 10); !ok {
			return big.NewInt(0), nil
		}
	case float64:
		b.SetInt64(int64(v))
	default:
		return big.NewInt(0), nil
	}
	// go-ethereum Pack for uint8/16/32/64 accepts *big.Int or native uint; Unpack returns byte/uint16/uint32/uint64 for small uints
	switch typ {
	case "uint8":
		if b.IsUint64() && b.Uint64() <= 0xff {
			return byte(b.Uint64()), nil // #nosec G115 -- bounds checked above
		}
		return big.NewInt(0), nil
	case "uint16":
		if b.IsUint64() && b.Uint64() <= 0xffff {
			return uint16(b.Uint64()), nil // #nosec G115 -- bounds checked above
		}
		return big.NewInt(0), nil
	case "uint32":
		if b.IsUint64() && b.Uint64() <= 0xffffffff {
			return uint32(b.Uint64()), nil // #nosec G115 -- bounds checked above
		}
		return big.NewInt(0), nil
	case "uint64":
		if b.IsUint64() {
			return b.Uint64(), nil
		}
		return big.NewInt(0), nil
	default:
		return &b, nil
	}
}

func toBigIntOrInt(val interface{}, typ string) (interface{}, error) {
	var b big.Int
	switch v := val.(type) {
	case string:
		if _, ok := b.SetString(v, 10); !ok {
			return big.NewInt(0), nil
		}
	case float64:
		b.SetInt64(int64(v))
	default:
		return big.NewInt(0), nil
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
