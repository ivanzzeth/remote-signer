package simulation

import (
	"context"
	"strings"
)

// parseRegistryEvents resolves unknown logs via the signature registry with strict ABI decode.
func parseRegistryEvents(ctx context.Context, reg *SignatureRegistry, logs []TxLog, builtinTopic0 map[string]struct{}) []SimEvent {
	if reg == nil || len(logs) == 0 {
		return nil
	}

	unknown := make([]TxLog, 0)
	topic0s := make([]string, 0)
	seen := make(map[string]struct{})
	for _, log := range logs {
		if len(log.Topics) == 0 {
			continue
		}
		t0 := strings.ToLower(log.Topics[0])
		if _, skip := builtinTopic0[t0]; skip {
			continue
		}
		unknown = append(unknown, log)
		if _, ok := seen[t0]; !ok {
			seen[t0] = struct{}{}
			topic0s = append(topic0s, t0)
		}
	}
	if len(topic0s) == 0 {
		return nil
	}

	lookup := reg.LookupEvents(ctx, topic0s...)
	if len(lookup) == 0 {
		return nil
	}

	out := make([]SimEvent, 0)
	for _, log := range unknown {
		t0 := strings.ToLower(log.Topics[0])
		key := strings.TrimPrefix(t0, "0x")
		candidates := lookup[key]
		if len(candidates) == 0 {
			continue
		}

		var matched []string
		var bestArgs map[string]string
		var bestSig string
		for _, sig := range candidates {
			args, ok := strictDecodeEventLog(sig, log)
			if !ok {
				continue
			}
			matched = append(matched, sig)
			if bestSig == "" {
				bestSig = sig
				bestArgs = args
			}
		}
		if bestSig == "" {
			continue
		}

		out = append(out, SimEvent{
			Address:    strings.ToLower(log.Address),
			Event:      eventNameFromSignature(bestSig),
			Standard:   "custom",
			Args:       bestArgs,
			Topic0:     t0,
			Signature:  bestSig,
			Source:     sourceRegistry,
			Confidence: confidenceInferred,
			Candidates: matched,
		})
	}
	return out
}

var builtinEventTopics = map[string]struct{}{
	strings.ToLower(transferTopic0):         {},
	strings.ToLower(transferSingleTopic0): {},
	strings.ToLower(transferBatchTopic0):  {},
	strings.ToLower(depositTopic0):          {},
	strings.ToLower(withdrawalTopic0):       {},
	strings.ToLower(approvalTopic0):         {},
	strings.ToLower(approvalForAllTopic0):   {},
}
