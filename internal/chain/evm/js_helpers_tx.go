// Package evm provides the EVM chain implementation including rule evaluation,
// signer management, and transaction processing for the remote-signer daemon.
package evm

import (
	"strings"

	"github.com/grafana/sobek"
)

const (
	// Enough for typical Safe execTransaction calldata; prevents huge-string DoS.
	rsMaxSafeExecTxCalldataHexLen = 256_000 // hex chars (without 0x)
)

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
			panic(vm.ToValue("missing input"))
		}
		inputEx := call.Argument(0).Export()
		inputMap, ok := inputEx.(map[string]interface{})
		if !ok {
			panic(vm.ToValue("invalid input"))
		}
		signType, _ := inputMap["sign_type"].(string)
		if signType != "transaction" {
			panic(vm.ToValue("transaction only"))
		}
		txRaw := inputMap["transaction"]
		if txRaw == nil {
			panic(vm.ToValue("missing tx fields"))
		}
		txMap, ok := txRaw.(map[string]interface{})
		if !ok {
			panic(vm.ToValue("missing tx fields"))
		}
		if _, hasTo := txMap["to"]; !hasTo {
			panic(vm.ToValue("missing tx fields"))
		}
		dataRaw := txMap["data"]
		if dataRaw == nil {
			panic(vm.ToValue("missing tx fields"))
		}
		dataStr := ""
		if s, ok := dataRaw.(string); ok {
			dataStr = s
		}
		dataHex := strings.TrimPrefix(strings.TrimPrefix(dataStr, "0x"), "0X")
		if len(dataHex) < 8 {
			panic(vm.ToValue("calldata too short"))
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
