package evm

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"
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
	if err := vm.Set("abi", abiObj); err != nil {
		return err
	}
	return injectRsHelpers(vm)
}

// injectRsHelpers injects the rs (remote-signer) module: rs.tx, rs.addr, rs.uint256, rs.typedData.
// Composable, safe API for evm_js rules. Only "rs" is reserved; do not use as variable name.
func injectRsHelpers(vm *sobek.Runtime) error {
	rs := vm.NewObject()

	// rs.tx
	txObj := vm.NewObject()
	if err := txObj.Set("require", vm.ToValue(rsTxRequire(vm))); err != nil {
		return err
	}
	if err := txObj.Set("getCalldata", vm.ToValue(rsTxGetCalldata(vm))); err != nil {
		return err
	}
	if err := rs.Set("tx", txObj); err != nil {
		return err
	}

	// rs.addr
	addrObj := vm.NewObject()
	if err := addrObj.Set("inList", vm.ToValue(rsAddrInList(vm))); err != nil {
		return err
	}
	if err := addrObj.Set("requireInList", vm.ToValue(rsAddrRequireInList(vm))); err != nil {
		return err
	}
	if err := addrObj.Set("requireInListIfNonEmpty", vm.ToValue(rsAddrRequireInListIfNonEmpty(vm))); err != nil {
		return err
	}
	if err := addrObj.Set("isZero", vm.ToValue(rsAddrIsZero(vm))); err != nil {
		return err
	}
	if err := addrObj.Set("requireZero", vm.ToValue(rsAddrRequireZero(vm))); err != nil {
		return err
	}
	if err := rs.Set("addr", addrObj); err != nil {
		return err
	}

	// rs.uint256
	uint256Obj := vm.NewObject()
	if err := uint256Obj.Set("cmp", vm.ToValue(rsUint256Cmp(vm))); err != nil {
		return err
	}
	if err := uint256Obj.Set("lt", vm.ToValue(rsUint256Lt(vm))); err != nil {
		return err
	}
	if err := uint256Obj.Set("lte", vm.ToValue(rsUint256Lte(vm))); err != nil {
		return err
	}
	if err := uint256Obj.Set("gt", vm.ToValue(rsUint256Gt(vm))); err != nil {
		return err
	}
	if err := uint256Obj.Set("gte", vm.ToValue(rsUint256Gte(vm))); err != nil {
		return err
	}
	if err := uint256Obj.Set("requireLte", vm.ToValue(rsUint256RequireLte(vm))); err != nil {
		return err
	}
	if err := rs.Set("uint256", uint256Obj); err != nil {
		return err
	}

	// rs.typedData
	typedDataObj := vm.NewObject()
	if err := typedDataObj.Set("require", vm.ToValue(rsTypedDataRequire(vm))); err != nil {
		return err
	}
	if err := typedDataObj.Set("requireDomain", vm.ToValue(rsTypedDataRequireDomain(vm))); err != nil {
		return err
	}
	if err := typedDataObj.Set("requireSignerMatch", vm.ToValue(rsTypedDataRequireSignerMatch(vm))); err != nil {
		return err
	}
	if err := rs.Set("typedData", typedDataObj); err != nil {
		return err
	}

	// rs.multisend — Gnosis MultiSend batch parsing
	multisendObj := vm.NewObject()
	if err := multisendObj.Set("parseBatch", vm.ToValue(rsMultisendParseBatch(vm))); err != nil {
		return err
	}
	if err := rs.Set("multisend", multisendObj); err != nil {
		return err
	}

	// rs.delegate — resolve rule ID by target address
	delegateObj := vm.NewObject()
	if err := delegateObj.Set("resolveByTarget", vm.ToValue(rsDelegateResolveByTarget(vm))); err != nil {
		return err
	}
	if err := rs.Set("delegate", delegateObj); err != nil {
		return err
	}

	// rs.hex — hex value checks
	hexObj := vm.NewObject()
	if err := hexObj.Set("requireZero32", vm.ToValue(rsHexRequireZero32(vm))); err != nil {
		return err
	}
	if err := rs.Set("hex", hexObj); err != nil {
		return err
	}

	return vm.Set("rs", rs)
}

func rsFail(vm *sobek.Runtime, reason string) sobek.Value {
	return vm.ToValue(map[string]interface{}{"valid": false, "reason": reason})
}

func rsOk(vm *sobek.Runtime) sobek.Value {
	return vm.ToValue(map[string]interface{}{"valid": true})
}

func rsTxRequire(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 || call.Argument(0) == nil || call.Argument(0).Equals(sobek.Undefined()) {
			return rsFail(vm, "missing input")
		}
		inputEx := call.Argument(0).Export()
		inputMap, ok := inputEx.(map[string]interface{})
		if !ok {
			return rsFail(vm, "invalid input")
		}
		signType, _ := inputMap["sign_type"].(string)
		if signType != "transaction" {
			return rsFail(vm, "transaction only")
		}
		txRaw := inputMap["transaction"]
		if txRaw == nil {
			return rsFail(vm, "missing tx fields")
		}
		txMap, ok := txRaw.(map[string]interface{})
		if !ok {
			return rsFail(vm, "missing tx fields")
		}
		if _, hasTo := txMap["to"]; !hasTo {
			return rsFail(vm, "missing tx fields")
		}
		dataRaw := txMap["data"]
		if dataRaw == nil {
			return rsFail(vm, "missing tx fields")
		}
		dataStr := ""
		if s, ok := dataRaw.(string); ok {
			dataStr = s
		}
		dataHex := strings.TrimPrefix(strings.TrimPrefix(dataStr, "0x"), "0X")
		if len(dataHex) < 8 {
			return rsFail(vm, "calldata too short")
		}
		sel := "0x" + dataHex[:8]
		payloadHex := "0x" + dataHex[8:]
		return vm.ToValue(map[string]interface{}{
			"valid":      true,
			"tx":         txMap,
			"selector":   sel,
			"payloadHex": payloadHex,
		})
	}
}

func rsTxGetCalldata(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 || call.Argument(0) == nil || call.Argument(0).Equals(sobek.Undefined()) {
			return rsFail(vm, "missing tx")
		}
		txRaw := call.Argument(0).Export()
		txMap, ok := txRaw.(map[string]interface{})
		if !ok {
			return rsFail(vm, "invalid tx")
		}
		dataRaw := txMap["data"]
		dataStr := ""
		if s, ok := dataRaw.(string); ok {
			dataStr = s
		}
		dataHex := strings.TrimPrefix(strings.TrimPrefix(dataStr, "0x"), "0X")
		if len(dataHex) < 8 {
			return rsFail(vm, "calldata too short")
		}
		sel := "0x" + dataHex[:8]
		payloadHex := "0x" + dataHex[8:]
		return vm.ToValue(map[string]interface{}{
			"valid":      true,
			"selector":   sel,
			"payloadHex": payloadHex,
		})
	}
}

func rsAddrInList(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue(false)
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		if !common.IsHexAddress(addrStr) {
			return vm.ToValue(false)
		}
		addrChecksum := common.HexToAddress(addrStr).Hex()
		listRaw := call.Argument(1).Export()
		var addrs []string
		switch v := listRaw.(type) {
		case []interface{}:
			for _, e := range v {
				if s, ok := e.(string); ok {
					s = strings.TrimSpace(s)
					if common.IsHexAddress(s) {
						addrs = append(addrs, common.HexToAddress(s).Hex())
					}
				}
			}
		case string:
			for _, part := range strings.Split(v, ",") {
				s := strings.TrimSpace(part)
				if s != "" && common.IsHexAddress(s) {
					addrs = append(addrs, common.HexToAddress(s).Hex())
				}
			}
		}
		for _, a := range addrs {
			if addrChecksum == a {
				return vm.ToValue(true)
			}
		}
		return vm.ToValue(false)
	}
}

func rsAddrRequireInList(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			return rsFail(vm, "requireInList needs addr, list, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		if !common.IsHexAddress(addrStr) {
			return rsFail(vm, reason)
		}
		addrChecksum := common.HexToAddress(addrStr).Hex()
		listRaw := call.Argument(1).Export()
		var addrs []string
		switch v := listRaw.(type) {
		case []interface{}:
			for _, e := range v {
				if s, ok := e.(string); ok {
					s = strings.TrimSpace(s)
					if common.IsHexAddress(s) {
						addrs = append(addrs, common.HexToAddress(s).Hex())
					}
				}
			}
		case string:
			for _, part := range strings.Split(v, ",") {
				s := strings.TrimSpace(part)
				if s != "" && common.IsHexAddress(s) {
					addrs = append(addrs, common.HexToAddress(s).Hex())
				}
			}
		}
		for _, a := range addrs {
			if addrChecksum == a {
				return rsOk(vm)
			}
		}
		return rsFail(vm, reason)
	}
}

// rsAddrRequireInListIfNonEmpty: when list is empty (array length 0 or string trim empty), returns ok().
// Otherwise same as requireInList.
func rsAddrRequireInListIfNonEmpty(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			return rsFail(vm, "requireInListIfNonEmpty needs addr, list, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		listRaw := call.Argument(1).Export()
		var addrs []string
		switch v := listRaw.(type) {
		case []interface{}:
			for _, e := range v {
				if s, ok := e.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" && common.IsHexAddress(s) {
						addrs = append(addrs, common.HexToAddress(s).Hex())
					}
				}
			}
		case string:
			for _, part := range strings.Split(v, ",") {
				s := strings.TrimSpace(part)
				if s != "" && common.IsHexAddress(s) {
					addrs = append(addrs, common.HexToAddress(s).Hex())
				}
			}
		}
		if len(addrs) == 0 {
			return rsOk(vm)
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		if !common.IsHexAddress(addrStr) {
			return rsFail(vm, reason)
		}
		addrChecksum := common.HexToAddress(addrStr).Hex()
		for _, a := range addrs {
			if addrChecksum == a {
				return rsOk(vm)
			}
		}
		return rsFail(vm, reason)
	}
}

func rsAddrIsZero(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 {
			return vm.ToValue(false)
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		zeroAddr := common.Address{}
		return vm.ToValue(common.IsHexAddress(addrStr) && common.HexToAddress(addrStr) == zeroAddr)
	}
}

func rsAddrRequireZero(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return rsFail(vm, "requireZero needs addr, reason")
		}
		reason := ""
		if r := call.Argument(1); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		zeroAddr := common.Address{}
		if !common.IsHexAddress(addrStr) || common.HexToAddress(addrStr) != zeroAddr {
			return rsFail(vm, reason)
		}
		return rsOk(vm)
	}
}

func rsUint256CmpInternal(a, b string) *int {
	sa := strings.TrimSpace(a)
	sb := strings.TrimSpace(b)
	if sa == "" || sb == "" {
		return nil
	}
	// SECURITY: Cap length to prevent CPU DoS from huge decimal strings (2^256 has 78 digits).
	if len(sa) > rsMaxUint256StrLen || len(sb) > rsMaxUint256StrLen {
		return nil
	}
	for _, r := range sa {
		if r < '0' || r > '9' {
			return nil
		}
	}
	for _, r := range sb {
		if r < '0' || r > '9' {
			return nil
		}
	}
	if len(sa) < len(sb) {
		v := -1
		return &v
	}
	if len(sa) > len(sb) {
		v := 1
		return &v
	}
	if sa < sb {
		v := -1
		return &v
	}
	if sa > sb {
		v := 1
		return &v
	}
	v := 0
	return &v
}

func rsUint256Cmp(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue(nil)
		}
		aStr := ""
		if v := call.Argument(0); v != nil && !v.Equals(sobek.Undefined()) {
			aStr = fmt.Sprintf("%v", v.Export())
		}
		bStr := ""
		if v := call.Argument(1); v != nil && !v.Equals(sobek.Undefined()) {
			bStr = fmt.Sprintf("%v", v.Export())
		}
		c := rsUint256CmpInternal(aStr, bStr)
		if c == nil {
			return vm.ToValue(nil)
		}
		return vm.ToValue(*c)
	}
}

func rsUint256Lt(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		c := rsUint256CmpInternal("", "")
		if len(call.Arguments) >= 2 {
			aStr := fmt.Sprintf("%v", call.Argument(0).Export())
			bStr := fmt.Sprintf("%v", call.Argument(1).Export())
			c = rsUint256CmpInternal(aStr, bStr)
		}
		return vm.ToValue(c != nil && *c < 0)
	}
}

func rsUint256Lte(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		c := rsUint256CmpInternal("", "")
		if len(call.Arguments) >= 2 {
			aStr := fmt.Sprintf("%v", call.Argument(0).Export())
			bStr := fmt.Sprintf("%v", call.Argument(1).Export())
			c = rsUint256CmpInternal(aStr, bStr)
		}
		return vm.ToValue(c != nil && *c <= 0)
	}
}

func rsUint256Gt(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		c := rsUint256CmpInternal("", "")
		if len(call.Arguments) >= 2 {
			aStr := fmt.Sprintf("%v", call.Argument(0).Export())
			bStr := fmt.Sprintf("%v", call.Argument(1).Export())
			c = rsUint256CmpInternal(aStr, bStr)
		}
		return vm.ToValue(c != nil && *c > 0)
	}
}

func rsUint256Gte(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		c := rsUint256CmpInternal("", "")
		if len(call.Arguments) >= 2 {
			aStr := fmt.Sprintf("%v", call.Argument(0).Export())
			bStr := fmt.Sprintf("%v", call.Argument(1).Export())
			c = rsUint256CmpInternal(aStr, bStr)
		}
		return vm.ToValue(c != nil && *c >= 0)
	}
}

// rsUint256RequireLte checks amount <= max. When max is empty or "0", no limit (returns ok).
// When max is invalid: fail(label + " cap invalid"). When amount is invalid: fail(label + " amount invalid").
// When amount > max: fail(label + " exceeds cap").
func rsUint256RequireLte(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			return rsFail(vm, "requireLte needs amount, max, label")
		}
		label := ""
		if l := call.Argument(2); l != nil && !l.Equals(sobek.Undefined()) {
			label = strings.TrimSpace(l.String())
		}
		maxStr := strings.TrimSpace(fmt.Sprintf("%v", call.Argument(1).Export()))
		if maxStr == "" || maxStr == "0" {
			return rsOk(vm)
		}
		if len(maxStr) > rsMaxUint256StrLen {
			return rsFail(vm, label+" cap invalid")
		}
		if !isDecimalString(maxStr) {
			return rsFail(vm, label+" cap invalid")
		}
		amStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			amStr = strings.TrimSpace(fmt.Sprintf("%v", a.Export()))
		}
		if len(amStr) > rsMaxUint256StrLen {
			return rsFail(vm, label+" amount invalid")
		}
		if amStr == "" || !isDecimalString(amStr) {
			return rsFail(vm, label+" amount invalid")
		}
		c := rsUint256CmpInternal(amStr, maxStr)
		if c == nil {
			return rsFail(vm, label+" amount invalid")
		}
		if *c > 0 {
			return rsFail(vm, label+" exceeds cap")
		}
		return rsOk(vm)
	}
}

func rsTypedDataRequire(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return rsFail(vm, "require needs input, primaryType")
		}
		primaryType := ""
		if p := call.Argument(1); p != nil && !p.Equals(sobek.Undefined()) {
			primaryType = strings.TrimSpace(p.String())
		}
		if primaryType == "" {
			return rsFail(vm, "primaryType required")
		}
		inputEx := call.Argument(0).Export()
		inputMap, ok := inputEx.(map[string]interface{})
		if !ok {
			return rsFail(vm, "invalid input")
		}
		signType, _ := inputMap["sign_type"].(string)
		if signType != "typed_data" {
			return rsFail(vm, "sign_type must be typed_data")
		}
		tdRaw := inputMap["typed_data"]
		if tdRaw == nil {
			return rsFail(vm, "not "+primaryType)
		}
		tdMap, ok := tdRaw.(map[string]interface{})
		if !ok {
			return rsFail(vm, "not "+primaryType)
		}
		pt, _ := tdMap["primaryType"].(string)
		if strings.TrimSpace(pt) != primaryType {
			return rsFail(vm, "not " + primaryType)
		}
		domain := map[string]interface{}{}
		if d, ok := tdMap["domain"].(map[string]interface{}); ok {
			domain = d
		}
		message := map[string]interface{}{}
		if m, ok := tdMap["message"].(map[string]interface{}); ok {
			message = m
		}
		return vm.ToValue(map[string]interface{}{
			"valid":  true,
			"domain": domain,
			"message": message,
		})
	}
}

func rsTypedDataRequireDomain(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return rsFail(vm, "requireDomain needs domain, opts")
		}
		domainEx := call.Argument(0).Export()
		domainMap, ok := domainEx.(map[string]interface{})
		if !ok {
			domainMap = map[string]interface{}{}
		}
		optsEx := call.Argument(1).Export()
		optsMap, ok := optsEx.(map[string]interface{})
		if !ok {
			return rsFail(vm, "invalid opts")
		}
		wantName, _ := optsMap["name"].(string)
		wantName = strings.TrimSpace(wantName)
		wantVersion, _ := optsMap["version"].(string)
		wantVersion = strings.TrimSpace(wantVersion)
		wantChainId := extractChainId(optsMap["chainId"])
		gotName := strings.TrimSpace(fmt.Sprintf("%v", domainMap["name"]))
		if gotName != wantName {
			return rsFail(vm, "invalid domain name")
		}
		gotVersion := ""
		if v, ok := domainMap["version"]; ok && v != nil {
			gotVersion = strings.TrimSpace(fmt.Sprintf("%v", v))
		}
		if gotVersion != wantVersion {
			return rsFail(vm, "invalid domain version")
		}
		gotChainId := extractChainId(domainMap["chainId"])
		if gotChainId != wantChainId {
			return rsFail(vm, "must be on configured chain")
		}
		vcRaw := domainMap["verifyingContract"]
		if vcRaw == nil {
			return rsFail(vm, "invalid verifying contract")
		}
		vcStr := strings.TrimSpace(fmt.Sprintf("%v", vcRaw))
		if !common.IsHexAddress(vcStr) {
			return rsFail(vm, "invalid verifying contract")
		}
		vcChecksum := common.HexToAddress(vcStr).Hex()
		allowedRaw, hasAllowed := optsMap["allowedContracts"]
		if hasAllowed {
			var allowed []string
			switch v := allowedRaw.(type) {
			case []interface{}:
				for _, e := range v {
					if s, ok := e.(string); ok {
						s = strings.TrimSpace(s)
						if common.IsHexAddress(s) {
							allowed = append(allowed, common.HexToAddress(s).Hex())
						}
					}
				}
			case string:
				for _, part := range strings.Split(v, ",") {
					s := strings.TrimSpace(part)
					if s != "" && common.IsHexAddress(s) {
						allowed = append(allowed, common.HexToAddress(s).Hex())
					}
				}
			}
			found := false
			for _, a := range allowed {
				if vcChecksum == a {
					found = true
					break
				}
			}
			if !found {
				return rsFail(vm, "invalid verifying contract")
			}
		}
		return rsOk(vm)
	}
}

func parseInt(s string) (int, bool) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err == nil
}

// extractChainId extracts chain ID from JS-exported value (string, float64, int, etc.).
// SECURITY: Clamps to int range; NaN/overflow yield 0.
func extractChainId(v interface{}) int {
	if v == nil {
		return 0
	}
	switch c := v.(type) {
	case string:
		n, _ := parseInt(c)
		return n
	case float64:
		if math.IsNaN(c) || math.IsInf(c, 0) {
			return 0
		}
		if c > float64(math.MaxInt) || c < float64(math.MinInt) {
			return 0
		}
		return int(c)
	case int:
		return c
	case int64:
		if c > int64(math.MaxInt) || c < int64(math.MinInt) {
			return 0
		}
		return int(c)
	default:
		n, _ := parseInt(fmt.Sprintf("%v", v))
		return n
	}
}

func rsTypedDataRequireSignerMatch(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			return rsFail(vm, "requireSignerMatch needs msgSigner, inputSigner, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		msgStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			msgStr = strings.TrimSpace(a.String())
		}
		inputStr := ""
		if a := call.Argument(1); a != nil && !a.Equals(sobek.Undefined()) {
			inputStr = strings.TrimSpace(a.String())
		}
		if !common.IsHexAddress(msgStr) || !common.IsHexAddress(inputStr) {
			return rsFail(vm, reason)
		}
		if common.HexToAddress(msgStr).Hex() != common.HexToAddress(inputStr).Hex() {
			return rsFail(vm, reason)
		}
		return rsOk(vm)
	}
}

// Security limits for rs helpers (DoS / overflow prevention).
const (
	rsMaxMultisendRawHexLen = 256 * 1024 // 128 KB raw = 256K hex chars (align with maxTransactionDataSize)
	rsMaxMultisendBatchLen = 64 * 1024  // max batch payload 64 KB
	rsMaxMultisendItemData = 32 * 1024  // max per-item data 32 KB
	rsMaxMultisendItems    = 256        // max items in batch
	rsMaxDelegatePairs     = 64         // max addr:rule_id pairs in resolveByTarget
	rsMaxUint256StrLen     = 78         // max decimal digits (2^256 has 78 digits)
)

// rsMultisendParseBatch parses Gnosis MultiSend(bytes) calldata. raw = hex without 0x.
// Returns { items: [...], err?: string }. Each item: { sign_type, chain_id, signer, transaction }.
// SECURITY: Bounds-checks raw length, batch length, data lengths; caps to prevent overflow/DoS.
func rsMultisendParseBatch(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			return vm.ToValue(map[string]interface{}{"err": "parseBatch needs raw, chainId, signer", "items": []interface{}{}})
		}
		raw := strings.TrimPrefix(strings.TrimPrefix(call.Argument(0).String(), "0x"), "0X")
		if len(raw) > rsMaxMultisendRawHexLen {
			return vm.ToValue(map[string]interface{}{"err": "calldata too large", "items": []interface{}{}})
		}
		if len(raw)%2 != 0 || !isHexString(raw) {
			return vm.ToValue(map[string]interface{}{"err": "invalid hex", "items": []interface{}{}})
		}
		chainId := 0
		if c := call.Argument(1); c != nil && !c.Equals(sobek.Undefined()) {
			rawChainId := fmt.Sprintf("%v", c.Export())
			n, ok := parseInt(rawChainId)
			if !ok {
				return vm.ToValue(map[string]interface{}{"err": "invalid chainId", "items": []interface{}{}})
			}
			chainId = n
		}
		signer := ""
		if s := call.Argument(2); s != nil && !s.Equals(sobek.Undefined()) {
			signer = strings.TrimSpace(s.String())
		}
		if len(raw) < 136 {
			return vm.ToValue(map[string]interface{}{"err": "calldata too short", "items": []interface{}{}})
		}
		lenBytes64, _ := strconv.ParseUint(raw[72:136], 16, 64)
		if lenBytes64 > uint64(rsMaxMultisendBatchLen) {
			return vm.ToValue(map[string]interface{}{"err": "batch too large", "items": []interface{}{}})
		}
		lenBytes := int(lenBytes64)
		batchStart := 136
		batchEnd := batchStart + lenBytes*2
		if batchEnd > len(raw) || batchEnd < batchStart {
			return vm.ToValue(map[string]interface{}{"err": "batch length mismatch", "items": []interface{}{}})
		}
		batchHex := raw[batchStart:batchEnd]
		var items []interface{}
		pos := 0
		for pos+170 <= len(batchHex) {
			if len(items) >= rsMaxMultisendItems {
				return vm.ToValue(map[string]interface{}{"err": "too many items", "items": items})
			}
			op := batchHex[pos : pos+2]
			pos += 2
			toHex := batchHex[pos : pos+40]
			pos += 40
			valueHex := "0x" + batchHex[pos:pos+64]
			pos += 64
			dataLen64, _ := strconv.ParseUint(batchHex[pos:pos+64], 16, 64)
			if dataLen64 > uint64(rsMaxMultisendItemData) {
				return vm.ToValue(map[string]interface{}{"err": "item data too large", "items": items})
			}
			dataLen := int(dataLen64)
			pos += 64
			dataEnd := pos + dataLen*2
			if dataEnd > len(batchHex) || dataEnd < pos {
				return vm.ToValue(map[string]interface{}{"err": "invalid data length", "items": items})
			}
			dataHex := "0x" + batchHex[pos:dataEnd]
			pos = dataEnd
			if op != "00" {
				return vm.ToValue(map[string]interface{}{"err": "only CALL (0) allowed", "items": items})
			}
			toAddr := "0x" + toHex[24:]
			if !common.IsHexAddress(toAddr) {
				return vm.ToValue(map[string]interface{}{"err": "invalid to address", "items": items})
			}
			items = append(items, map[string]interface{}{
				"sign_type":   "transaction",
				"chain_id":    chainId,
				"signer":      signer,
				"transaction": map[string]interface{}{"from": signer, "to": toAddr, "value": valueHex, "data": dataHex},
			})
		}
		return vm.ToValue(map[string]interface{}{"items": items})
	}
}

// rsDelegateResolveByTarget resolves delegate rule ID by inner target. byTarget = "addr:rule_id,addr:rule_id", defaultRule = fallback.
// SECURITY: Caps pair count to prevent CPU DoS.
func rsDelegateResolveByTarget(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			return vm.ToValue("")
		}
		innerTo := strings.TrimSpace(call.Argument(0).String())
		byTarget := strings.TrimSpace(call.Argument(1).String())
		defaultRule := strings.TrimSpace(call.Argument(2).String())
		if byTarget == "" {
			return vm.ToValue(defaultRule)
		}
		pairs := strings.Split(byTarget, ",")
		if len(pairs) > rsMaxDelegatePairs {
			return vm.ToValue(defaultRule)
		}
		innerChecksum := common.HexToAddress(innerTo).Hex()
		for _, pair := range pairs {
			idx := strings.Index(pair, ":")
			if idx <= 0 {
				continue
			}
			addr := strings.TrimSpace(pair[:idx])
			ruleId := strings.TrimSpace(pair[idx+1:])
			if common.IsHexAddress(addr) && ruleId != "" && common.HexToAddress(addr).Hex() == innerChecksum {
				return vm.ToValue(ruleId)
			}
		}
		return vm.ToValue(defaultRule)
	}
}

// rsHexRequireZero32 checks hexValue (32 bytes, no 0x) equals zero. Returns ok() or fail(reason).
// SECURITY: Rejects input > 64 hex chars to avoid memory/CPU abuse; pads/truncates only within 64.
func rsHexRequireZero32(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return rsFail(vm, "requireZero32 needs hexValue, reason")
		}
		hexVal := strings.TrimPrefix(strings.TrimPrefix(call.Argument(0).String(), "0x"), "0X")
		if len(hexVal) > 64 {
			return rsFail(vm, "hex value must be 32 bytes (64 hex chars)")
		}
		reason := ""
		if r := call.Argument(1); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		zero32 := "0000000000000000000000000000000000000000000000000000000000000000"
		if len(hexVal) < 64 {
			hexVal = strings.Repeat("0", 64-len(hexVal)) + hexVal
		}
		if hexVal != zero32 {
			return rsFail(vm, reason)
		}
		return rsOk(vm)
	}
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
