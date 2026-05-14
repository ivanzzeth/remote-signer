// Package evm provides the EVM chain implementation including rule evaluation,
// signer management, and transaction processing for the remote-signer daemon.
package evm

import (
	"fmt"
	"math"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/sobek"
)

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
