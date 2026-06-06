package simulation

import (
	"context"
	"strings"
)

// decodeRevertReason turns eth_call / eth_simulateV1 revert data into text.
// Prefer ResolveRevert for structured output; this helper remains for legacy callers.
func decodeRevertReason(data string) string {
	res := ResolveRevert(context.Background(), GlobalSignatureRegistry(), data)
	if res.Reason != "" {
		return res.Reason
	}
	return "transaction reverted"
}

// revertDataFromCall picks the best available revert payload from an
// eth_simulateV1 call result. Gateways often put custom errors in
// error.data while returnData stays empty.
func revertDataFromCall(returnData string, errData string) string {
	if d := strings.TrimSpace(returnData); d != "" && d != "0x" {
		return normalizeHex(d)
	}
	if d := strings.TrimSpace(errData); d != "" && d != "0x" {
		return normalizeHex(d)
	}
	return ""
}
