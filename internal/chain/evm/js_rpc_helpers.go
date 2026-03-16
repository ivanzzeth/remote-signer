package evm

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/sobek"
)

// RPCInjectionContext holds per-evaluation state for RPC helpers in the JS sandbox.
type RPCInjectionContext struct {
	ChainID  string
	Provider *RPCProvider
	Cache    *TokenMetadataCache
	Counter  *RPCCallCounter
	Ctx      context.Context
}

// injectRPCHelpers injects web3, erc20, erc165, isERC721, isERC1155 into the JS VM.
// rpcCtx may be nil — in that case all RPC calls throw "rpc not configured".
func injectRPCHelpers(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) error {
	if rpcCtx == nil {
		// Inject stubs that throw when called
		return injectRPCStubs(vm)
	}

	// web3 object
	web3Obj := vm.NewObject()
	if err := web3Obj.Set("call", vm.ToValue(jsWeb3Call(vm, rpcCtx))); err != nil {
		return err
	}
	if err := web3Obj.Set("getCode", vm.ToValue(jsWeb3GetCode(vm, rpcCtx))); err != nil {
		return err
	}
	if err := vm.Set("web3", web3Obj); err != nil {
		return err
	}

	// erc20 object
	erc20Obj := vm.NewObject()
	if err := erc20Obj.Set("decimals", vm.ToValue(jsERC20Decimals(vm, rpcCtx))); err != nil {
		return err
	}
	if err := erc20Obj.Set("symbol", vm.ToValue(jsERC20Symbol(vm, rpcCtx))); err != nil {
		return err
	}
	if err := erc20Obj.Set("name", vm.ToValue(jsERC20Name(vm, rpcCtx))); err != nil {
		return err
	}
	if err := vm.Set("erc20", erc20Obj); err != nil {
		return err
	}

	// erc165 object
	erc165Obj := vm.NewObject()
	if err := erc165Obj.Set("supportsInterface", vm.ToValue(jsERC165SupportsInterface(vm, rpcCtx))); err != nil {
		return err
	}
	if err := vm.Set("erc165", erc165Obj); err != nil {
		return err
	}

	// Top-level convenience functions
	if err := vm.Set("isERC721", vm.ToValue(jsIsERC721(vm, rpcCtx))); err != nil {
		return err
	}
	if err := vm.Set("isERC1155", vm.ToValue(jsIsERC1155(vm, rpcCtx))); err != nil {
		return err
	}

	return nil
}

// injectRPCStubs injects stub functions that throw when RPC is not configured.
func injectRPCStubs(vm *sobek.Runtime) error {
	stub := func(name string) func(sobek.FunctionCall) sobek.Value {
		return func(call sobek.FunctionCall) sobek.Value {
			panic(vm.ToValue(fmt.Sprintf("%s: rpc not configured", name)))
		}
	}

	web3Obj := vm.NewObject()
	if err := web3Obj.Set("call", vm.ToValue(stub("web3.call"))); err != nil {
		return err
	}
	if err := web3Obj.Set("getCode", vm.ToValue(stub("web3.getCode"))); err != nil {
		return err
	}
	if err := vm.Set("web3", web3Obj); err != nil {
		return err
	}

	erc20Obj := vm.NewObject()
	if err := erc20Obj.Set("decimals", vm.ToValue(stub("erc20.decimals"))); err != nil {
		return err
	}
	if err := erc20Obj.Set("symbol", vm.ToValue(stub("erc20.symbol"))); err != nil {
		return err
	}
	if err := erc20Obj.Set("name", vm.ToValue(stub("erc20.name"))); err != nil {
		return err
	}
	if err := vm.Set("erc20", erc20Obj); err != nil {
		return err
	}

	erc165Obj := vm.NewObject()
	if err := erc165Obj.Set("supportsInterface", vm.ToValue(stub("erc165.supportsInterface"))); err != nil {
		return err
	}
	if err := vm.Set("erc165", erc165Obj); err != nil {
		return err
	}

	if err := vm.Set("isERC721", vm.ToValue(stub("isERC721"))); err != nil {
		return err
	}
	if err := vm.Set("isERC1155", vm.ToValue(stub("isERC1155"))); err != nil {
		return err
	}

	return nil
}

// jsWeb3Call implements web3.call(to, data) → hex string
// SECURITY: address and data are validated before RPC call. ChainID comes from
// the sign request context (set server-side), never from JS code.
func jsWeb3Call(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			panic(vm.ToValue("web3.call requires (to, data)"))
		}
		to := strings.TrimSpace(call.Argument(0).String())
		data := strings.TrimSpace(call.Argument(1).String())

		if err := ValidateEthAddress(to); err != nil {
			panic(vm.ToValue(fmt.Sprintf("web3.call: %s", err)))
		}
		if err := ValidateHexData(data); err != nil {
			panic(vm.ToValue(fmt.Sprintf("web3.call: %s", err)))
		}

		result, err := rpcCtx.Provider.Call(rpcCtx.Ctx, rpcCtx.ChainID, to, data)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("web3.call: %s", err)))
		}
		return vm.ToValue(result)
	}
}

// jsWeb3GetCode implements web3.getCode(address) → hex string
func jsWeb3GetCode(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("web3.getCode requires (address)"))
		}
		addr := strings.TrimSpace(call.Argument(0).String())
		if err := ValidateEthAddress(addr); err != nil {
			panic(vm.ToValue(fmt.Sprintf("web3.getCode: %s", err)))
		}

		result, err := rpcCtx.Provider.GetCode(rpcCtx.Ctx, rpcCtx.ChainID, addr)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("web3.getCode: %s", err)))
		}
		return vm.ToValue(result)
	}
}

// jsERC20Decimals implements erc20.decimals(address) → number
func jsERC20Decimals(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("erc20.decimals requires (address)"))
		}
		addr := strings.TrimSpace(call.Argument(0).String())
		if err := ValidateEthAddress(addr); err != nil {
			panic(vm.ToValue(fmt.Sprintf("erc20.decimals: %s", err)))
		}

		decimals, err := rpcCtx.Cache.GetDecimals(rpcCtx.Ctx, rpcCtx.ChainID, addr, rpcCtx.Counter)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("erc20.decimals: %s", err)))
		}
		return vm.ToValue(decimals)
	}
}

// jsERC20Symbol implements erc20.symbol(address) → string
func jsERC20Symbol(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("erc20.symbol requires (address)"))
		}
		addr := strings.TrimSpace(call.Argument(0).String())
		if err := ValidateEthAddress(addr); err != nil {
			panic(vm.ToValue(fmt.Sprintf("erc20.symbol: %s", err)))
		}

		symbol, err := rpcCtx.Cache.GetSymbol(rpcCtx.Ctx, rpcCtx.ChainID, addr, rpcCtx.Counter)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("erc20.symbol: %s", err)))
		}
		return vm.ToValue(symbol)
	}
}

// jsERC20Name implements erc20.name(address) → string
func jsERC20Name(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("erc20.name requires (address)"))
		}
		addr := strings.TrimSpace(call.Argument(0).String())
		if err := ValidateEthAddress(addr); err != nil {
			panic(vm.ToValue(fmt.Sprintf("erc20.name: %s", err)))
		}

		name, err := rpcCtx.Cache.GetName(rpcCtx.Ctx, rpcCtx.ChainID, addr, rpcCtx.Counter)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("erc20.name: %s", err)))
		}
		return vm.ToValue(name)
	}
}

// jsERC165SupportsInterface implements erc165.supportsInterface(address, interfaceId) → bool
func jsERC165SupportsInterface(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 2 {
			panic(vm.ToValue("erc165.supportsInterface requires (address, interfaceId)"))
		}
		addr := strings.TrimSpace(call.Argument(0).String())
		ifaceID := strings.TrimSpace(call.Argument(1).String())
		if err := ValidateEthAddress(addr); err != nil {
			panic(vm.ToValue(fmt.Sprintf("erc165.supportsInterface: %s", err)))
		}

		result, err := rpcCtx.Cache.SupportsInterface(rpcCtx.Ctx, rpcCtx.ChainID, addr, ifaceID, rpcCtx.Counter)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("erc165.supportsInterface: %s", err)))
		}
		return vm.ToValue(result)
	}
}

// jsIsERC721 implements isERC721(address) → bool
func jsIsERC721(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("isERC721 requires (address)"))
		}
		addr := strings.TrimSpace(call.Argument(0).String())
		if err := ValidateEthAddress(addr); err != nil {
			panic(vm.ToValue(fmt.Sprintf("isERC721: %s", err)))
		}

		result, err := rpcCtx.Cache.IsERC721(rpcCtx.Ctx, rpcCtx.ChainID, addr, rpcCtx.Counter)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("isERC721: %s", err)))
		}
		return vm.ToValue(result)
	}
}

// jsIsERC1155 implements isERC1155(address) → bool
func jsIsERC1155(vm *sobek.Runtime, rpcCtx *RPCInjectionContext) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		if len(call.Arguments) < 1 {
			panic(vm.ToValue("isERC1155 requires (address)"))
		}
		addr := strings.TrimSpace(call.Argument(0).String())
		if err := ValidateEthAddress(addr); err != nil {
			panic(vm.ToValue(fmt.Sprintf("isERC1155: %s", err)))
		}

		result, err := rpcCtx.Cache.IsERC1155(rpcCtx.Ctx, rpcCtx.ChainID, addr, rpcCtx.Counter)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("isERC1155: %s", err)))
		}
		return vm.ToValue(result)
	}
}
