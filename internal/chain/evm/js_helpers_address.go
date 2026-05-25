// Package evm provides the EVM chain implementation including rule evaluation,
// signer management, and transaction processing for the remote-signer daemon.
package evm

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/sobek"
)

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
	case []string:
		for _, s := range v {
			if checksum, ok := rsAddrNormalize(s); ok {
				addrs = append(addrs, checksum)
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
			panic(vm.ToValue("requireInList needs addr, list, reason"))
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
		panic(vm.ToValue(reason))
	}
}

func rsAddrRequireNotInList(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic(vm.ToValue("requireNotInList needs addr, list, reason"))
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
			panic(vm.ToValue(reason))
		}
		listRaw := call.Argument(1).Export()
		if !rsAddrInListCore(addrStr, listRaw) {
			return rsOk(vm)
		}
		panic(vm.ToValue(reason))
	}
}

// rsAddrRequireInListIfNonEmpty: when list is empty (array length 0 or string trim empty), returns ok().
// Otherwise same as requireInList. On failure panics so engine turns it into fail (one-line usage).
func rsAddrRequireInListIfNonEmpty(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 3 {
			panic(vm.ToValue("requireInListIfNonEmpty needs addr, list, reason"))
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
			panic(vm.ToValue(reason))
		}
		for _, a := range addrs {
			if addrChecksum == a {
				return rsOk(vm)
			}
		}
		panic(vm.ToValue(reason))
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
			panic(vm.ToValue("requireZero needs addr, reason"))
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
			panic(vm.ToValue(reason))
		}
		return rsOk(vm)
	}
}

// rsAddrToChecksumList converts a JS array or comma-separated string of addresses
// to a checksummed array. Invalid addresses are silently skipped.
func rsAddrToChecksumList(vm *sobek.Runtime) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 {
			return vm.ToValue([]string{})
		}
		listRaw := call.Argument(0).Export()
		addrs := rsAddrListFromExport(listRaw)
		return vm.ToValue(addrs)
	}
}
