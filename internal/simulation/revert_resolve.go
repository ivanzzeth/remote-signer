package simulation

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// RevertResolution is the structured output of revert decoding.
type RevertResolution struct {
	Reason       string
	Data         string
	Selector     string
	Signature    string
	Source       string
	Confidence   string
	DecodedArgs  map[string]string `json:"decoded_args,omitempty"`
	Candidates   []string          `json:"candidates,omitempty"`
}

// ResolveRevert decodes revert data using builtin decoders first, then the signature registry.
func ResolveRevert(ctx context.Context, reg *SignatureRegistry, data string) RevertResolution {
	data = normalizeHex(data)
	hex := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(data)), "0x")
	res := RevertResolution{
		Data:       data,
		Source:       sourceRegistry,
		Confidence: confidenceUnknown,
	}
	if len(hex) < 8 {
		res.Reason = "transaction reverted"
		return res
	}

	res.Selector = "0x" + hex[:8]

	if reason, ok := decodeBuiltinRevert(hex); ok {
		res.Reason = reason
		res.Signature = builtinRevertSignature(hex[:8])
		res.Source = sourceBuiltin
		res.Confidence = confidenceVerified
		return res
	}

	if reg == nil {
		res.Reason = fmt.Sprintf("transaction reverted (selector %s)", res.Selector)
		return res
	}

	candidates := reg.LookupFunctions(ctx, res.Selector)[strings.TrimPrefix(res.Selector, "0x")]
	if len(candidates) == 0 {
		res.Reason = fmt.Sprintf("transaction reverted (selector %s)", res.Selector)
		return res
	}

	res.Candidates = append([]string(nil), candidates...)
	for _, sig := range candidates {
		args, ok := strictDecodeRevertData(sig, data)
		if !ok {
			continue
		}
		res.Signature = sig
		res.Source = sourceRegistry
		res.Confidence = confidenceInferred
		res.DecodedArgs = args
		res.Reason = formatRevertReason(sig, args)
		return res
	}

	// Zero-arg errors may not need payload beyond selector.
	for _, sig := range candidates {
		_, types, err := splitCallableSignature(sig)
		if err == nil && len(types) == 0 && len(hex) == 8 {
			res.Signature = sig
			res.Source = sourceRegistry
			res.Confidence = confidenceInferred
			res.Reason = sig
			return res
		}
	}

	res.Reason = fmt.Sprintf("transaction reverted (selector %s)", res.Selector)
	return res
}

func decodeBuiltinRevert(hex string) (string, bool) {
	selector := hex[:8]
	switch selector {
	case "08c379a0":
		msg, err := abi.UnpackRevert(commonHexBytes(hex))
		if err == nil && msg != "" {
			return msg, true
		}
	case "4e487b71":
		if len(hex) >= 72 {
			// Panic(uint256) — surface code for debugging.
			word := hex[8:72]
			return fmt.Sprintf("Panic(0x%s)", strings.TrimLeft(word, "0")), true
		}
		return "Panic(uint256)", true
	}
	return "", false
}

func builtinRevertSignature(selector string) string {
	switch selector {
	case "08c379a0":
		return "Error(string)"
	case "4e487b71":
		return "Panic(uint256)"
	default:
		return ""
	}
}

func formatRevertReason(sig string, args map[string]string) string {
	if len(args) == 0 {
		return sig
	}
	parts := make([]string, 0, len(args))
	for k, v := range args {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return sig + " (" + strings.Join(parts, ", ") + ")"
}

func commonHexBytes(hexStr string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(hexStr), "0x"))
	if err != nil {
		return nil
	}
	return b
}
