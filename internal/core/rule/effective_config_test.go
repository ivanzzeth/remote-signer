package rule

import (
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestResolveEffectiveRule_VariableChangeIsLive is the core guarantee of the
// Option A design: the effective Config an evaluator sees is derived from the
// rule's Variables at evaluation time. Editing Variables (the single source of
// truth) changes the effective Config immediately — there is no rendered
// snapshot to drift, and the stored template-form Config never changes.
func TestResolveEffectiveRule_VariableChangeIsLive(t *testing.T) {
	const tmplConfig = `{"addresses":["${recipient}"]}`
	mk := func(vars string) *types.Rule {
		return &types.Rule{
			ID:        "inst_x",
			Type:      types.RuleTypeEVMAddressList,
			Mode:      types.RuleModeWhitelist,
			Config:    []byte(tmplConfig),
			Variables: []byte(vars),
		}
	}

	eff1 := resolveEffectiveRule(mk(`{"recipient":"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), "137")
	if !strings.Contains(string(eff1.Config), "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatalf("effective config should contain the bound recipient, got %s", eff1.Config)
	}

	// Simulate a Variables update (e.g. via PATCH): same template-form Config,
	// new Variables. The effective config must reflect the new value.
	eff2 := resolveEffectiveRule(mk(`{"recipient":"0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}`), "137")
	if !strings.Contains(string(eff2.Config), "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") {
		t.Fatalf("effective config should reflect updated recipient, got %s", eff2.Config)
	}
	if strings.Contains(string(eff2.Config), "${recipient}") {
		t.Fatalf("effective config must not contain unresolved placeholder, got %s", eff2.Config)
	}
}

func TestResolveEffectiveRule_InjectsChainID(t *testing.T) {
	r := &types.Rule{
		ID:        "inst_c",
		Type:      types.RuleTypeEVMJS,
		Config:    []byte(`{"chain":"${chain_id}"}`),
		Variables: []byte(`{}`),
	}
	eff := resolveEffectiveRule(r, "56")
	if string(eff.Config) != `{"chain":"56"}` {
		t.Fatalf("chain_id should be injected from the request, got %s", eff.Config)
	}
}

func TestResolveEffectiveRule_MatrixOverlay(t *testing.T) {
	r := &types.Rule{
		ID:        "inst_m",
		Type:      types.RuleTypeEVMAddressList,
		Config:    []byte(`{"token":"${token}"}`),
		Variables: []byte(`{"token":"0xDEFAULT"}`),
		Matrix:    []byte(`[{"chain_id":"137","token":"0xPOLYGON"},{"chain_id":"56","token":"0xBNB"}]`),
	}
	if got := string(resolveEffectiveRule(r, "137").Config); got != `{"token":"0xPOLYGON"}` {
		t.Fatalf("matrix row for 137 should override token, got %s", got)
	}
	if got := string(resolveEffectiveRule(r, "56").Config); got != `{"token":"0xBNB"}` {
		t.Fatalf("matrix row for 56 should override token, got %s", got)
	}
	if got := string(resolveEffectiveRule(r, "1").Config); got != `{"token":"0xDEFAULT"}` {
		t.Fatalf("no matrix row for 1 should keep the default, got %s", got)
	}
}

func TestResolveEffectiveRule_DirectRulePassthrough(t *testing.T) {
	r := &types.Rule{
		ID:     "rule_direct",
		Type:   types.RuleTypeEVMAddressList,
		Config: []byte(`{"addresses":["0xCAFE"]}`),
		// No Variables: a directly-created rule. Config must be returned as-is,
		// same pointer, no substitution.
	}
	eff := resolveEffectiveRule(r, "137")
	if eff != r {
		t.Fatal("direct rule (no Variables) should be returned unchanged, same pointer")
	}
}
