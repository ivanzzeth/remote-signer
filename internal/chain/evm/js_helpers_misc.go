package evm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/sobek"
)

// Security limits for rs helpers (DoS / overflow prevention).
const (
	rsMaxMultisendRawHexLen = 256 * 1024 // 128 KB raw = 256K hex chars (align with maxTransactionDataSize)
	rsMaxMultisendBatchLen  = 64 * 1024  // max batch payload 64 KB
	rsMaxMultisendItemData  = 32 * 1024  // max per-item data 32 KB
	rsMaxMultisendItems     = 256        // max items in batch
	rsMaxDelegatePairs      = 64         // max addr:rule_id pairs in resolveByTarget
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
