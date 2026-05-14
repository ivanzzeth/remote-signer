package evm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

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
