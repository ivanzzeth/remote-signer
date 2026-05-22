// Package evm provides the EVM chain implementation including rule evaluation,
// signer management, and transaction processing for the remote-signer daemon.
package evm

import (
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/grafana/sobek"
)

const (
	rsMaxBigIntInputLen = 128 // characters (input string before parsing)
	rsMaxIntInputLen    = 32  // characters (input string before parsing)
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
	dec = strings.TrimPrefix(dec, "+")
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
