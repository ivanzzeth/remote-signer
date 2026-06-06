package simulation

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const (
	sourceBuiltin   = "builtin"
	sourceRegistry  = "registry"
	confidenceVerified = "verified"
	confidenceInferred = "inferred"
	confidenceUnknown  = "unknown"
)

// splitCallableSignature parses "Name(type,type)" into name and ABI type strings.
func splitCallableSignature(sig string) (name string, types []string, err error) {
	sig = strings.TrimSpace(sig)
	open := strings.Index(sig, "(")
	if open < 0 {
		return "", nil, fmt.Errorf("signature missing '('")
	}
	name = strings.TrimSpace(sig[:open])
	close := strings.LastIndex(sig, ")")
	if close <= open {
		return "", nil, fmt.Errorf("signature missing ')'")
	}
	inner := strings.TrimSpace(sig[open+1 : close])
	if inner == "" {
		return name, nil, nil
	}
	types = splitCommaRespectingParens(inner)
	for i, t := range types {
		types[i] = normalizeABITypeToken(t)
	}
	return name, types, nil
}

func splitCommaRespectingParens(s string) []string {
	var parts []string
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '(', '[':
			depth++
			b.WriteRune(r)
		case ')', ']':
			depth--
			b.WriteRune(r)
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(b.String()))
				b.Reset()
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	if tail := strings.TrimSpace(b.String()); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

func normalizeABITypeToken(tok string) string {
	tok = strings.TrimSpace(tok)
	fields := strings.Fields(tok)
	if len(fields) == 0 {
		return tok
	}
	// Drop "indexed" and param names; keep last token as type (may include brackets).
	if len(fields) == 1 {
		return fields[0]
	}
	last := fields[len(fields)-1]
	if strings.Contains(last, "(") || strings.Contains(last, "[") {
		return last
	}
	// name + type pair: transfer(address) style inside event
	if len(fields) >= 2 {
		return fields[len(fields)-1]
	}
	return tok
}

func buildArguments(types []string, indexedCount int) (abi.Arguments, error) {
	if indexedCount < 0 || indexedCount > len(types) {
		return nil, fmt.Errorf("indexed count out of range")
	}
	args := make(abi.Arguments, len(types))
	for i, t := range types {
		typ, err := abi.NewType(t, "", nil)
		if err != nil {
			return nil, err
		}
		args[i] = abi.Argument{
			Name:    fmt.Sprintf("arg%d", i),
			Type:    typ,
			Indexed: i < indexedCount,
		}
	}
	return args, nil
}

// strictDecodeEventLog attempts ABI decode of a log for the given event signature.
// indexedCount is inferred from len(topics)-1. Returns false when decode fails.
func strictDecodeEventLog(sig string, log TxLog) (map[string]string, bool) {
	_, types, err := splitCallableSignature(sig)
	if err != nil || len(log.Topics) == 0 {
		return nil, false
	}
	indexedCount := len(log.Topics) - 1
	if indexedCount > len(types) {
		return nil, false
	}

	args, err := buildArguments(types, indexedCount)
	if err != nil {
		return nil, false
	}

	var indexedArgs abi.Arguments
	var dataArgs abi.Arguments
	for _, a := range args {
		if a.Indexed {
			indexedArgs = append(indexedArgs, a)
		} else {
			dataArgs = append(dataArgs, a)
		}
	}

	data := common.FromHex(log.Data)
	if len(dataArgs) > 0 {
		if len(data)%32 != 0 {
			return nil, false
		}
	}

	out := make(map[string]string)

	if len(indexedArgs) > 0 {
		if len(log.Topics)-1 != len(indexedArgs) {
			return nil, false
		}
		topicHashes := make([]common.Hash, len(log.Topics)-1)
		for i, t := range log.Topics[1:] {
			topicHashes[i] = common.HexToHash(t)
		}
		idxMap := make(map[string]interface{})
		if err := abi.ParseTopicsIntoMap(idxMap, indexedArgs, topicHashes); err != nil {
			return nil, false
		}
		for k, v := range idxMap {
			out[k] = formatABIValue(v)
		}
	} else if len(log.Topics) > 1 {
		return nil, false
	}

	if len(dataArgs) > 0 {
		vals, err := dataArgs.Unpack(data)
		if err != nil {
			return nil, false
		}
		for i, a := range dataArgs {
			out[a.Name] = formatABIValue(vals[i])
		}
	} else if trimHexPrefix(log.Data) != "" {
		hex := strings.ToLower(trimHexPrefix(log.Data))
		if hex != "" && hex != "0" {
			return nil, false
		}
	}

	return out, true
}

// strictDecodeRevertData decodes revert payload for a custom error signature.
func strictDecodeRevertData(sig string, dataHex string) (map[string]string, bool) {
	name, types, err := splitCallableSignature(sig)
	if err != nil {
		return nil, false
	}
	_ = name

	args, err := buildArguments(types, 0)
	if err != nil {
		return nil, false
	}
	if len(args) == 0 {
		return map[string]string{}, true
	}

	raw := common.FromHex(dataHex)
	if len(raw) < 4 {
		return nil, false
	}
	payload := raw[4:]
	if len(payload) == 0 {
		return map[string]string{}, true
	}
	if len(payload)%32 != 0 {
		return nil, false
	}

	vals, err := args.Unpack(payload)
	if err != nil {
		return nil, false
	}
	out := make(map[string]string, len(args))
	for i, a := range args {
		out[a.Name] = formatABIValue(vals[i])
	}
	return out, true
}

func formatABIValue(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return "0x" + common.Bytes2Hex(x)
	case common.Address:
		return x.Hex()
	case *big.Int:
		return x.String()
	case bool:
		if x {
			return "true"
		}
		return "false"
	case [32]byte:
		return "0x" + common.Bytes2Hex(x[:])
	default:
		return fmt.Sprint(v)
	}
}

func eventNameFromSignature(sig string) string {
	name, _, err := splitCallableSignature(sig)
	if err != nil {
		return sig
	}
	return name
}

func verifiedEventsOnly(events []SimEvent) []SimEvent {
	if len(events) == 0 {
		return events
	}
	out := make([]SimEvent, 0, len(events))
	for _, e := range events {
		if e.Confidence == "" || e.Confidence == confidenceVerified {
			out = append(out, e)
		}
	}
	return out
}
