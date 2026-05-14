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

// SAFETY: All rs.* require/assert functions panic on failure. The caller (wrappedValidate)
// MUST have defer/recover to catch panics and convert them into fail results. Never call
// rs.* helper functions outside wrappedValidate without proper panic recovery.

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
	// revert(reason) and require(cond, reason) — global primitives; throw so engine turns exception into fail.
	if _, err := vm.RunString(`function revert(r){ throw new Error(typeof r === "string" ? r : (r != null ? String(r) : "reverted")); } function require(cond, r){ if (!cond) revert(r); }`); err != nil {
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
	if err := addrObj.Set("notInList", vm.ToValue(rsAddrNotInList(vm))); err != nil {
		return err
	}
	if err := addrObj.Set("requireInList", vm.ToValue(rsAddrRequireInList(vm))); err != nil {
		return err
	}
	if err := addrObj.Set("requireNotInList", vm.ToValue(rsAddrRequireNotInList(vm))); err != nil {
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

	// rs.int — strict integer parsing
	intObj := vm.NewObject()
	if err := intObj.Set("parseUint", vm.ToValue(rsIntParseUint(vm))); err != nil {
		return err
	}
	if err := intObj.Set("requireLte", vm.ToValue(rsIntRequireLte(vm))); err != nil {
		return err
	}
	if err := intObj.Set("requireEq", vm.ToValue(rsIntRequireEq(vm))); err != nil {
		return err
	}
	if err := rs.Set("int", intObj); err != nil {
		return err
	}

	// rs.bigint — convert inputs into JavaScript BigInt (replaces rs.uint256)
	bigintObj := vm.NewObject()
	if err := bigintObj.Set("parse", vm.ToValue(rsBigIntParse(vm))); err != nil {
		return err
	}
	if err := bigintObj.Set("uint256", vm.ToValue(rsBigIntUint256(vm))); err != nil {
		return err
	}
	if err := bigintObj.Set("int256", vm.ToValue(rsBigIntInt256(vm))); err != nil {
		return err
	}
	if err := bigintObj.Set("requireLte", vm.ToValue(rsBigIntRequireLte(vm))); err != nil {
		return err
	}
	if err := bigintObj.Set("requireEq", vm.ToValue(rsBigIntRequireEq(vm))); err != nil {
		return err
	}
	if err := bigintObj.Set("requireZero", vm.ToValue(rsBigIntRequireZero(vm))); err != nil {
		return err
	}
	if err := rs.Set("bigint", bigintObj); err != nil {
		return err
	}

	// rs.typedData
	typedDataObj := vm.NewObject()
	if err := typedDataObj.Set("match", vm.ToValue(rsTypedDataMatch(vm))); err != nil {
		return err
	}
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

	// rs.config — requireNonEmpty(key, reason). Config string values are trimmed when injected (see js_evaluator).
	configObj := vm.NewObject()
	if err := configObj.Set("requireNonEmpty", vm.ToValue(rsConfigRequireNonEmpty(vm))); err != nil {
		return err
	}
	if err := rs.Set("config", configObj); err != nil {
		return err
	}

	// rs.gnosis.safe — Gnosis Safe helpers (namespaced to avoid global pollution)
	gnosisObj := vm.NewObject()
	safeObj := vm.NewObject()
	if err := safeObj.Set("parseExecTransactionData", vm.ToValue(rsSafeParseExecTransactionData(vm))); err != nil {
		return err
	}
	if err := gnosisObj.Set("safe", safeObj); err != nil {
		return err
	}
	if err := rs.Set("gnosis", gnosisObj); err != nil {
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

// rsConfigRequireNonEmpty panics with reason if config[key] is missing or trimmed empty.
// Config is injected with strings already trimmed (see trimConfigStrings in js_evaluator).
func rsConfigRequireNonEmpty(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			panic("requireNonEmpty needs key, reason")
		}
		key := strings.TrimSpace(call.Argument(0).String())
		reason := ""
		if r := call.Argument(1); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		configVal := vm.Get("config")
		if configVal == nil || configVal.Equals(sobek.Undefined()) {
			panic(reason)
		}
		configMap, _ := configVal.Export().(map[string]interface{})
		if configMap == nil {
			panic(reason)
		}
		v, exists := configMap[key]
		if !exists || v == nil {
			panic(reason)
		}
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s == "" {
			panic(reason)
		}
		return rsOk(vm)
	}
}

const (
	// Enough for typical Safe execTransaction calldata; prevents huge-string DoS.
	rsMaxSafeExecTxCalldataHexLen = 256_000 // hex chars (without 0x)
	rsMaxBigIntInputLen           = 128     // characters (input string before parsing)
	rsMaxIntInputLen              = 32      // characters (input string before parsing)
)

var (
	rsUint256Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)) // 2^256 - 1
	rsInt256Min  = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 255))                // -2^255
	rsInt256Max  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)) // 2^255 - 1
)

func parseUint256HexToUint64Strict(hex256 string) (uint64, bool) {
	hex256 = strings.TrimSpace(hex256)
	if hex256 == "" {
		return 0, false
	}
	// Allow 0x prefix (defensive).
	hex256 = strings.TrimPrefix(strings.TrimPrefix(hex256, "0x"), "0X")
	if len(hex256) > 64 {
		return 0, false
	}
	// Left pad to 64 (the caller often slices exact 64 already, but keep robust).
	if len(hex256) < 64 {
		hex256 = strings.Repeat("0", 64-len(hex256)) + hex256
	}
	// Must fit into uint64.
	prefix := hex256[:48]
	for i := 0; i < len(prefix); i++ {
		if prefix[i] != '0' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(hex256[48:], 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseBigIntStrict(v interface{}) (*big.Int, bool) {
	// Normalize input into a bounded string representation first (prevents DoS).
	var s string
	switch x := v.(type) {
	case string:
		s = strings.TrimSpace(x)
	case int:
		s = strconv.Itoa(x)
	case int64:
		s = strconv.FormatInt(x, 10)
	case uint64:
		s = strconv.FormatUint(x, 10)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		if x != math.Trunc(x) {
			return nil, false
		}
		if x > float64(math.MaxInt64) || x < float64(math.MinInt64) {
			return nil, false
		}
		s = strconv.FormatInt(int64(x), 10)
	default:
		return nil, false
	}

	if s == "" || len(s) > rsMaxBigIntInputLen {
		return nil, false
	}

	n := new(big.Int)
	// Support 0x... hex and decimal.
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		hexStr := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		if hexStr == "" || len(hexStr) > 64 || !isHexString(hexStr) {
			return nil, false
		}
		if _, ok := n.SetString(hexStr, 16); !ok {
			return nil, false
		}
		return n, true
	}

	dec := s
	if strings.HasPrefix(dec, "+") {
		dec = dec[1:]
	}
	if dec == "" || len(dec) > rsMaxBigIntInputLen {
		return nil, false
	}
	start := 0
	if dec[0] == '-' {
		start = 1
	}
	if start >= len(dec) {
		return nil, false
	}
	for i := start; i < len(dec); i++ {
		if dec[i] < '0' || dec[i] > '9' {
			return nil, false
		}
	}
	if _, ok := n.SetString(dec, 10); !ok {
		return nil, false
	}
	return n, true
}

func toJSBigInt(vm *sobek.Runtime, n *big.Int) (sobek.Value, bool) {
	bigIntCtor := vm.Get("BigInt")
	fn, ok := sobek.AssertFunction(bigIntCtor)
	if !ok {
		return nil, false
	}
	vBig, err := fn(sobek.Undefined(), vm.ToValue(n.String()))
	if err != nil {
		return nil, false
	}
	return vBig, true
}

func rsBigIntParse(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 || call.Argument(0) == nil || call.Argument(0).Equals(sobek.Undefined()) {
			return rsFail(vm, "missing value")
		}
		n, ok := parseBigIntStrict(call.Argument(0).Export())
		if !ok {
			return rsFail(vm, "invalid value")
		}
		vBig, ok := toJSBigInt(vm, n)
		if !ok {
			return rsFail(vm, "BigInt not supported")
		}
		return vm.ToValue(map[string]interface{}{
			"valid": true,
			"n":     vBig,
		})
	}
}

func rsBigIntUint256(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 || call.Argument(0) == nil || call.Argument(0).Equals(sobek.Undefined()) {
			return rsFail(vm, "missing value")
		}
		n, ok := parseBigIntStrict(call.Argument(0).Export())
		if !ok {
			return rsFail(vm, "invalid uint256")
		}
		if n.Sign() < 0 || n.Cmp(rsUint256Max) > 0 {
			return rsFail(vm, "invalid uint256")
		}
		vBig, ok := toJSBigInt(vm, n)
		if !ok {
			return rsFail(vm, "BigInt not supported")
		}
		return vm.ToValue(map[string]interface{}{"valid": true, "n": vBig})
	}
}

func rsBigIntInt256(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 || call.Argument(0) == nil || call.Argument(0).Equals(sobek.Undefined()) {
			return rsFail(vm, "missing value")
		}
		n, ok := parseBigIntStrict(call.Argument(0).Export())
		if !ok {
			return rsFail(vm, "invalid int256")
		}
		if n.Cmp(rsInt256Min) < 0 || n.Cmp(rsInt256Max) > 0 {
			return rsFail(vm, "invalid int256")
		}
		vBig, ok := toJSBigInt(vm, n)
		if !ok {
			return rsFail(vm, "BigInt not supported")
		}
		return vm.ToValue(map[string]interface{}{"valid": true, "n": vBig})
	}
}

func rsBigIntRequireLte(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic("requireLte needs a, b, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		maxRaw := call.Argument(1).Export()
		if s, ok := maxRaw.(string); ok {
			s = strings.TrimSpace(s)
			// Only "-1" = no cap (convention). Empty string is invalid and will fail below.
			if s == "-1" {
				return rsOk(vm)
			}
		}
		a, ok := parseBigIntStrict(call.Argument(0).Export())
		if !ok {
			panic(reason)
		}
		b, ok := parseBigIntStrict(maxRaw)
		if !ok {
			panic(reason)
		}
		if a.Cmp(b) > 0 {
			panic(reason)
		}
		return rsOk(vm)
	}
}

func rsBigIntRequireZero(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			panic("requireZero needs amount, reason")
		}
		reason := ""
		if r := call.Argument(1); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		n, ok := parseBigIntStrict(call.Argument(0).Export())
		if !ok {
			panic(reason)
		}
		if n.Sign() != 0 {
			panic(reason)
		}
		return rsOk(vm)
	}
}

func rsBigIntRequireEq(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic("requireEq needs a, b, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		a, ok := parseBigIntStrict(call.Argument(0).Export())
		if !ok {
			panic(reason)
		}
		b, ok := parseBigIntStrict(call.Argument(1).Export())
		if !ok {
			panic(reason)
		}
		if a.Cmp(b) != 0 {
			panic(reason)
		}
		return rsOk(vm)
	}
}

func parseUintStrict(v interface{}) (uint64, bool) {
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s == "" || len(s) > rsMaxIntInputLen {
			return 0, false
		}
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
		}
		u, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return u, true
	case int:
		if x < 0 {
			return 0, false
		}
		return uint64(x), true
	case int64:
		if x < 0 {
			return 0, false
		}
		return uint64(x), true
	case uint64:
		return x, true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, false
		}
		// float64 can only represent integers exactly up to 2^53; reject larger values to avoid precision loss.
		if x != math.Trunc(x) || x < 0 || x > float64(1<<53) {
			return 0, false
		}
		return uint64(x), true
	default:
		return 0, false
	}
}

func rsIntParseUint(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 || call.Argument(0) == nil || call.Argument(0).Equals(sobek.Undefined()) {
			return rsFail(vm, "missing value")
		}
		u, ok := parseUintStrict(call.Argument(0).Export())
		if !ok {
			return rsFail(vm, "invalid value")
		}
		return vm.ToValue(map[string]interface{}{"valid": true, "n": u})
	}
}

func rsIntRequireLte(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic("requireLte needs value, max, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		u, ok := parseUintStrict(call.Argument(0).Export())
		if !ok {
			panic(reason)
		}
		max, ok := parseUintStrict(call.Argument(1).Export())
		if !ok {
			panic(reason)
		}
		if u > max {
			panic(reason)
		}
		return rsOk(vm)
	}
}

func rsIntRequireEq(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic("requireEq needs value, want, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		u, ok := parseUintStrict(call.Argument(0).Export())
		if !ok {
			panic(reason)
		}
		want, ok := parseUintStrict(call.Argument(1).Export())
		if !ok {
			panic(reason)
		}
		if u != want {
			panic(reason)
		}
		return rsOk(vm)
	}
}

func rsSafeParseExecTransactionData(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 || call.Argument(0) == nil || call.Argument(0).Equals(sobek.Undefined()) {
			return rsFail(vm, "missing calldata")
		}
		dataRaw, ok := call.Argument(0).Export().(string)
		if !ok {
			return rsFail(vm, "invalid calldata")
		}
		raw := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(dataRaw), "0x"), "0X")
		if raw == "" {
			return rsFail(vm, "data too short")
		}
		if len(raw) > rsMaxSafeExecTxCalldataHexLen {
			return rsFail(vm, "calldata too large")
		}
		if len(raw)%2 != 0 || !isHexString(raw) {
			return rsFail(vm, "invalid calldata")
		}
		// Need selector(4 bytes) + first 4 head slots to parse:
		// to, value, dataOffset, operation.
		// selector=8 hex chars, slots=64 hex chars each → 8 + 64*4 = 264.
		if len(raw) < 8+64*4 {
			return rsFail(vm, "data too short")
		}

		// to: first arg is 32 bytes, address is last 20 bytes.
		toHex := "0x" + raw[8+24:8+64]

		// value: second arg slot must be all zeros.
		valueHex := raw[8+64 : 8+64*2]
		valueZero := true
		for i := 0; i < len(valueHex); i++ {
			if valueHex[i] != '0' {
				valueZero = false
				break
			}
		}

		// operation: 4th arg is uint8 encoded in a 32-byte slot; last byte indicates operation.
		opLastByteHex := raw[8+64*3+62 : 8+64*4]
		operationCALL := strings.EqualFold(opLastByteHex, "00")

		// data offset: third arg.
		dataOffsetHex := raw[8+64*2 : 8+64*3]
		dataOffset, ok := parseUint256HexToUint64Strict(dataOffsetHex)
		if !ok {
			return rsFail(vm, "invalid data offset")
		}
		rawLen := uint64(len(raw))
		// Overflow guard: dataOffset*2 and subsequent additions must not wrap around.
		if dataOffset > rawLen/2 {
			return rsFail(vm, "invalid data offset")
		}
		base := uint64(8) + dataOffset*2
		if base+64 > rawLen {
			return rsFail(vm, "invalid data offset")
		}
		innerLenHex := raw[base : base+64]
		innerLen, ok := parseUint256HexToUint64Strict(innerLenHex)
		if !ok {
			return rsFail(vm, "invalid inner data length")
		}
		innerStart := base + 64
		// Overflow guard: innerLen*2 must not wrap around.
		if innerLen > rawLen/2 {
			return rsFail(vm, "invalid inner data length")
		}
		innerEnd := innerStart + innerLen*2
		if innerEnd > rawLen {
			return rsFail(vm, "invalid inner data length")
		}
		innerHex := "0x" + raw[innerStart:innerEnd]
		return vm.ToValue(map[string]interface{}{
			"valid":         true,
			"valueZero":     valueZero,
			"operationCALL": operationCALL,
			"innerTo":       toHex,
			"innerHex":      innerHex,
		})
	}
}

func rsTxRequire(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 || call.Argument(0) == nil || call.Argument(0).Equals(sobek.Undefined()) {
			panic("missing input")
		}
		inputEx := call.Argument(0).Export()
		inputMap, ok := inputEx.(map[string]interface{})
		if !ok {
			panic("invalid input")
		}
		signType, _ := inputMap["sign_type"].(string)
		if signType != "transaction" {
			panic("transaction only")
		}
		txRaw := inputMap["transaction"]
		if txRaw == nil {
			panic("missing tx fields")
		}
		txMap, ok := txRaw.(map[string]interface{})
		if !ok {
			panic("missing tx fields")
		}
		if _, hasTo := txMap["to"]; !hasTo {
			panic("missing tx fields")
		}
		dataRaw := txMap["data"]
		if dataRaw == nil {
			panic("missing tx fields")
		}
		dataStr := ""
		if s, ok := dataRaw.(string); ok {
			dataStr = s
		}
		dataHex := strings.TrimPrefix(strings.TrimPrefix(dataStr, "0x"), "0X")
		if len(dataHex) < 8 {
			panic("calldata too short")
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

func rsAddrNormalize(addrStr string) (string, bool) {
	addrStr = strings.TrimSpace(addrStr)
	if !common.IsHexAddress(addrStr) {
		return "", false
	}
	return common.HexToAddress(addrStr).Hex(), true
}

func rsAddrListFromExport(listRaw interface{}) []string {
	var addrs []string
	switch v := listRaw.(type) {
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok {
				if checksum, ok := rsAddrNormalize(s); ok {
					addrs = append(addrs, checksum)
				}
			}
		}
	case string:
		for _, part := range strings.Split(v, ",") {
			if checksum, ok := rsAddrNormalize(part); ok {
				addrs = append(addrs, checksum)
			}
		}
	}
	return addrs
}

func rsAddrInListCore(addrStr string, listRaw interface{}) bool {
	addrChecksum, ok := rsAddrNormalize(addrStr)
	if !ok {
		return false
	}
	for _, a := range rsAddrListFromExport(listRaw) {
		if addrChecksum == a {
			return true
		}
	}
	return false
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
		listRaw := call.Argument(1).Export()
		return vm.ToValue(rsAddrInListCore(addrStr, listRaw))
	}
}

func rsAddrNotInList(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue(true)
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		listRaw := call.Argument(1).Export()
		return vm.ToValue(!rsAddrInListCore(addrStr, listRaw))
	}
}

func rsAddrRequireInList(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic("requireInList needs addr, list, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		listRaw := call.Argument(1).Export()
		if rsAddrInListCore(addrStr, listRaw) {
			return rsOk(vm)
		}
		panic(reason)
	}
}

func rsAddrRequireNotInList(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic("requireNotInList needs addr, list, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		// Validate address first to prevent malformed addresses from bypassing blocklist.
		if _, ok := rsAddrNormalize(addrStr); !ok {
			panic(reason)
		}
		listRaw := call.Argument(1).Export()
		if !rsAddrInListCore(addrStr, listRaw) {
			return rsOk(vm)
		}
		panic(reason)
	}
}

// rsAddrRequireInListIfNonEmpty: when list is empty (array length 0 or string trim empty), returns ok().
// Otherwise same as requireInList. On failure panics so engine turns it into fail (one-line usage).
func rsAddrRequireInListIfNonEmpty(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic("requireInListIfNonEmpty needs addr, list, reason")
		}
		reason := ""
		if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
			reason = r.String()
		}
		listRaw := call.Argument(1).Export()
		addrs := rsAddrListFromExport(listRaw)
		if len(addrs) == 0 {
			return rsOk(vm)
		}
		addrStr := ""
		if a := call.Argument(0); a != nil && !a.Equals(sobek.Undefined()) {
			addrStr = strings.TrimSpace(a.String())
		}
		addrChecksum, ok := rsAddrNormalize(addrStr)
		if !ok {
			panic(reason)
		}
		for _, a := range addrs {
			if addrChecksum == a {
				return rsOk(vm)
			}
		}
		panic(reason)
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
			panic("requireZero needs addr, reason")
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
			panic(reason)
		}
		return rsOk(vm)
	}
}

func rsTypedDataRequire(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			panic("require needs input, primaryType")
		}
		primaryType := ""
		if p := call.Argument(1); p != nil && !p.Equals(sobek.Undefined()) {
			primaryType = strings.TrimSpace(p.String())
		}
		if primaryType == "" {
			panic("primaryType required")
		}
		inputEx := call.Argument(0).Export()
		inputMap, ok := inputEx.(map[string]interface{})
		if !ok {
			panic("invalid input")
		}
		signType, _ := inputMap["sign_type"].(string)
		if signType != "typed_data" {
			panic("sign_type must be typed_data")
		}
		tdRaw := inputMap["typed_data"]
		if tdRaw == nil {
			panic("not " + primaryType)
		}
		tdMap, ok := tdRaw.(map[string]interface{})
		if !ok {
			panic("not " + primaryType)
		}
		pt, _ := tdMap["primaryType"].(string)
		if strings.TrimSpace(pt) != primaryType {
			panic("not " + primaryType)
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
			"valid":   true,
			"domain":  domain,
			"message": message,
		})
	}
}

// rsTypedDataMatch checks whether input is typed_data with matching primaryType.
// It is intended for "soft match" in rules (e.g. blocklist: not matched -> ok()).
// Returns { matched: true, domain, message } or { matched: false }.
func rsTypedDataMatch(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue(map[string]interface{}{"matched": false})
		}
		primaryType := ""
		if p := call.Argument(1); p != nil && !p.Equals(sobek.Undefined()) {
			primaryType = strings.TrimSpace(p.String())
		}
		if primaryType == "" {
			return vm.ToValue(map[string]interface{}{"matched": false})
		}
		inputEx := call.Argument(0).Export()
		inputMap, ok := inputEx.(map[string]interface{})
		if !ok {
			return vm.ToValue(map[string]interface{}{"matched": false})
		}
		signType, _ := inputMap["sign_type"].(string)
		if signType != "typed_data" {
			return vm.ToValue(map[string]interface{}{"matched": false})
		}
		tdRaw := inputMap["typed_data"]
		if tdRaw == nil {
			return vm.ToValue(map[string]interface{}{"matched": false})
		}
		tdMap, ok := tdRaw.(map[string]interface{})
		if !ok {
			return vm.ToValue(map[string]interface{}{"matched": false})
		}
		pt, _ := tdMap["primaryType"].(string)
		if strings.TrimSpace(pt) != primaryType {
			return vm.ToValue(map[string]interface{}{"matched": false})
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
			"matched": true,
			"domain":  domain,
			"message": message,
		})
	}
}

func rsTypedDataRequireDomain(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			panic("requireDomain needs domain, opts")
		}
		domainEx := call.Argument(0).Export()
		domainMap, ok := domainEx.(map[string]interface{})
		if !ok {
			domainMap = map[string]interface{}{}
		}
		optsEx := call.Argument(1).Export()
		optsMap, ok := optsEx.(map[string]interface{})
		if !ok {
			panic("invalid opts")
		}
		wantName, hasName := optsMap["name"].(string)
		if hasName {
			wantName = strings.TrimSpace(wantName)
		}
		wantVersion, hasVersion := optsMap["version"].(string)
		if hasVersion {
			wantVersion = strings.TrimSpace(wantVersion)
		}
		wantChainId := extractChainId(optsMap["chainId"])
		if hasName {
			gotName := strings.TrimSpace(fmt.Sprintf("%v", domainMap["name"]))
			if gotName != wantName {
				panic("invalid domain name")
			}
		}
		if hasVersion {
			gotVersion := ""
			if v, ok := domainMap["version"]; ok && v != nil {
				gotVersion = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
			if gotVersion != wantVersion {
				panic("invalid domain version")
			}
		}
		gotChainId := extractChainId(domainMap["chainId"])
		if gotChainId != wantChainId {
			chainReason := "must be on configured chain"
			if len(call.Arguments) >= 3 {
				if r := call.Argument(2); r != nil && !r.Equals(sobek.Undefined()) {
					if s := strings.TrimSpace(r.String()); s != "" {
						chainReason = s
					}
				}
			}
			panic(chainReason)
		}
		requireVC := true
		if b, ok := optsMap["requireVerifyingContract"].(bool); ok {
			requireVC = b
		}
		allowedRaw, hasAllowed := optsMap["allowedContracts"]
		if !requireVC && !hasAllowed {
			return rsOk(vm)
		}
		vcRaw := domainMap["verifyingContract"]
		if vcRaw == nil {
			panic("invalid verifying contract")
		}
		vcStr := strings.TrimSpace(fmt.Sprintf("%v", vcRaw))
		if !common.IsHexAddress(vcStr) {
			panic("invalid verifying contract")
		}
		vcChecksum := common.HexToAddress(vcStr).Hex()
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
				panic("invalid verifying contract")
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
			panic("requireSignerMatch needs msgSigner, inputSigner, reason")
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
			panic(reason)
		}
		if common.HexToAddress(msgStr).Hex() != common.HexToAddress(inputStr).Hex() {
			panic(reason)
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
