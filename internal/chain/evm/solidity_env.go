package evm

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Helper functions

func formatAddress(addr *string) string {
	if addr == nil || *addr == "" {
		return "address(0)"
	}
	// Defense in depth: validate hex format before embedding in Solidity.
	// Invalid addresses would cause forge compilation errors and could
	// poison the shared compilation directory (forge compiles all .sol files).
	if !common.IsHexAddress(*addr) {
		return "address(0)"
	}
	// Solidity requires EIP-55 checksummed addresses.
	// common.HexToAddress().Hex() returns the properly checksummed form.
	return common.HexToAddress(*addr).Hex()
}

func formatWei(value *string) string {
	if value == nil || *value == "" {
		return "0"
	}
	// Defense in depth: validate only decimal digits to prevent Solidity template injection.
	// Embedded as: uint256 value = {{.Value}};
	if !isDecimalString(*value) {
		return "0"
	}
	return *value
}

func formatSelector(sig *string) string {
	if sig == nil || *sig == "" {
		return "bytes4(0)"
	}
	// Defense in depth: validate hex to prevent Solidity template injection.
	// Embedded as: bytes4 selector = {{.Selector}};
	s := strings.TrimPrefix(*sig, "0x")
	if !isHexString(s) || len(s) != 8 {
		return "bytes4(0)"
	}
	return fmt.Sprintf("bytes4(0x%s)", s)
}

func formatBytes(data []byte) string {
	if len(data) == 0 {
		return "hex\"\""
	}
	return fmt.Sprintf("hex\"%s\"", hex.EncodeToString(data))
}

// addressForEnv returns a hex address string for env vars (vm.envAddress expects raw hex, not Solidity literals).
func addressForEnv(addr *string) string {
	if addr == nil || *addr == "" {
		return "0x0000000000000000000000000000000000000000"
	}
	s := strings.TrimPrefix(*addr, "0x")
	if !isHexString(s) || len(s) != 40 {
		return "0x0000000000000000000000000000000000000000"
	}
	if !common.IsHexAddress(*addr) {
		return "0x0000000000000000000000000000000000000000"
	}
	return common.HexToAddress(*addr).Hex()
}

// buildRequestEnv returns environment variables for request-as-input execution.
// Script reads these via vm.envAddress, vm.envUint, vm.envBytes so the same compiled artifact can be reused.
func buildRequestEnv(req *types.SignRequest, parsed *types.ParsedPayload) []string {
	if req == nil || parsed == nil {
		return nil
	}
	dataHex := "0x"
	if len(parsed.RawData) > 0 {
		dataHex = "0x" + hex.EncodeToString(parsed.RawData)
	}
	selectorHex := "0x00000000"
	if parsed.MethodSig != nil && strings.TrimPrefix(*parsed.MethodSig, "0x") != "" {
		s := strings.TrimPrefix(*parsed.MethodSig, "0x")
		if isHexString(s) && len(s) == 8 {
			selectorHex = "0x" + s
		}
	}
	chainID := req.ChainID
	if chainID == "" || !isDecimalString(chainID) {
		chainID = "1"
	}
	value := "0"
	if parsed.Value != nil && *parsed.Value != "" && isDecimalString(*parsed.Value) {
		value = *parsed.Value
	}
	return []string{
		envRuleTxTo + "=" + addressForEnv(parsed.Recipient),
		envRuleTxValue + "=" + value,
		envRuleTxSelector + "=" + selectorHex,
		envRuleTxData + "=" + dataHex,
		envRuleChainID + "=" + chainID,
		envRuleSigner + "=" + addressForEnv(&req.SignerAddress),
	}
}

func formatChainID(chainID string) string {
	if chainID == "" {
		return "1"
	}
	// Defense in depth: validate only decimal digits to prevent Solidity template injection.
	// Embedded as: uint256 chainId = {{.ChainID}};
	if !isDecimalString(chainID) {
		return "1"
	}
	return chainID
}
