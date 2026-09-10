package evm

import (
	"sort"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func typeSet(m map[types.RuleType]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

func assertSet(t *testing.T, got []string, want []string, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", what, got, want)
		}
	}
}

// TestBlockedRuleTypes_ExactSets pins the RBAC outcome, not the mechanism.
//
// ⚠️ These two sets were literals until 2026-09-10 and are now derived from
// descriptor flags in types.ruleTypes. That is a better default — a new engine
// is blocked for agents by being described, rather than permitted by omission —
// but it also means a mistyped descriptor is a silent permission change. This
// test is the thing that makes it loud.
//
// ⛔ If this test fails, do not update the expectation to match. Work out which
// descriptor flag moved and whether widening that role's authority was intended.
func TestBlockedRuleTypes_ExactSets(t *testing.T) {
	assertSet(t, typeSet(blockedAgentRuleTypes), []string{
		"evm_js",                  // executes operator-supplied code
		"evm_solidity_expression", // executes operator-supplied code
		"signer_restriction",      // decides which signers may be used at all
	}, "blockedAgentRuleTypes")

	assertSet(t, typeSet(blockedDevRuleTypes), []string{
		"signer_restriction",
	}, "blockedDevRuleTypes")
}

// TestEveryCodeExecutingEngineIsBlockedForAgents states the invariant directly,
// so it survives a future engine rather than only describing today's three.
func TestEveryCodeExecutingEngineIsBlockedForAgents(t *testing.T) {
	for _, d := range types.RuleTypes() {
		if d.ExecutesArbitraryCode && !blockedAgentRuleTypes[d.Type] {
			t.Errorf("%s executes arbitrary code but agents may create it", d.Type)
		}
		if d.GovernsSignerAccess && !blockedDevRuleTypes[d.Type] {
			t.Errorf("%s governs signer access but dev may create it", d.Type)
		}
	}
}
