package rule

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/ports"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func delegatingRule(id, to string) *types.Rule {
	cfg, _ := json.Marshal(map[string]string{"delegate_to": to})
	return &types.Rule{ID: types.RuleID(id), Name: id, Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist, Enabled: true, Config: cfg}
}

// TestAddDelegationTargets_BrokenConfigIsAnError pins the semantics the two
// deleted copies disagreed on.
//
// One of them read an unparseable config as "delegates to nothing", so the
// isolated engine validated the rule without its delegation chain and reported
// a pass — for a rule that at evaluation time would have delegated somewhere.
// A rule whose delegation cannot be determined has not been validated.
func TestAddDelegationTargets_BrokenConfigIsAnError(t *testing.T) {
	broken := &types.Rule{ID: "r1", Name: "broken", Type: types.RuleTypeEVMJS, Config: []byte(`{not json`)}
	repo := ports.NewMemoryRuleRepository()

	err := AddDelegationTargets(context.Background(), broken,
		map[types.RuleID]*types.Rule{"r1": broken}, repo,
		map[types.RuleID]bool{}, slog.Default())

	if err == nil {
		t.Fatal("a config that cannot be read must be an error, not silently treated as non-delegating")
	}
	if !strings.Contains(err.Error(), "r1") {
		t.Errorf("error should name the rule, got %v", err)
	}
}

// TestAddDelegationTargets_WalksTheChain covers the ordinary path and the cycle
// guard: delegation is recursive, and a cycle would otherwise not terminate.
func TestAddDelegationTargets_WalksTheChain(t *testing.T) {
	a, b, c := delegatingRule("a", "b"), delegatingRule("b", "c"), delegatingRule("c", "a")
	all := map[types.RuleID]*types.Rule{"a": a, "b": b, "c": c}
	repo := ports.NewMemoryRuleRepository()

	if err := AddDelegationTargets(context.Background(), a, all, repo, map[types.RuleID]bool{}, slog.Default()); err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, id := range []types.RuleID{"b", "c"} {
		if _, err := repo.Get(context.Background(), id); err != nil {
			t.Errorf("delegation target %s not added to the isolated repo: %v", id, err)
		}
	}
}
