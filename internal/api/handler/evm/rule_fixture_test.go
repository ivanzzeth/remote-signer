package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------- the rule family's route-test fixture (proposal S8) ----------
//
// ⚠️ Exported, and in `package evm` rather than `package evm_test`, for the same
// reason RequestRouteFixture is: the route tests live in the external test
// package (they import internal/api, which imports this one), and an external
// test file can only reach exported identifiers — but it *can* reach ones
// declared in this package's own _test.go files, which is where a fixture
// belongs.
//
// ⭐ Every spy here records an *effect*. That is the whole point of it. The
// guards the decomposition removes were asserted by "the handler answered 400"
// or "…405", and a handler that writes a row and *then* answers 400 passes that
// check. What replaces it is "the rule table still has exactly the rows it
// started with, and its status is unchanged".

// RuleRouteID is a rule id shaped like the ones the API mints: rule.go's
// ruleIDPattern accepts `rule_<uuid>`, and internal/core/rule creates exactly
// that. ⛔ It contains no '/' — no form ruleIDPattern accepts does — which is
// why {id} needs no percent-encoding anywhere in this surface.
const RuleRouteID = "rule_00000000-0000-0000-0000-000000000001"

// RuleRouteAdminKey holds every permission and role the rule routes ask for, so
// a request that reaches a handler gets all the way through. ⛔ Without that, a
// refusal could be a 403 a test mistakes for "the route did not match".
func RuleRouteAdminKey() *types.APIKey {
	return &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
}

// RuleRouteAgentKey is a non-admin key, for the two validate endpoints whose
// admin check lives inside the handler rather than on the route.
func RuleRouteAgentKey() *types.APIKey {
	return &types.APIKey{ID: "agent-key", Name: "Agent", Role: types.RoleAgent, Enabled: true}
}

// RuleRouteFixture holds the rule handler over an in-memory repository whose
// contents the route tests read back after every request.
type RuleRouteFixture struct {
	Handler *RuleHandler

	repo         *mockRuleRepo
	budgetLists  []string
	budgetResets []string
}

// NewRuleRouteFixture builds a RuleHandler holding one pending-approval rule,
// with a budget repository wired — the configuration in which all twelve named
// routes exist.
//
// ⚠️ Pending rather than active on purpose: approve and reject both refuse a
// rule in any other state with a 400, so an active rule would make "nothing
// happened" indistinguishable from "the route did not match".
func NewRuleRouteFixture(t *testing.T) *RuleRouteFixture {
	t.Helper()
	repo := newMockRuleRepo()
	r := newAPIRule()
	r.ID = RuleRouteID
	r.Owner = "admin-key"
	r.Status = types.RuleStatusPendingApproval
	repo.addRule(r)

	fx := &RuleRouteFixture{repo: repo}
	budgets := &mockBudgetRepo{
		listByRuleID: func(_ context.Context, id types.RuleID) ([]*types.RuleBudget, error) {
			fx.budgetLists = append(fx.budgetLists, string(id))
			return []*types.RuleBudget{}, nil
		},
		resetFn: func(_ context.Context, id types.RuleID, unit string, _ time.Time) error {
			fx.budgetResets = append(fx.budgetResets, string(id)+"/"+unit)
			return nil
		},
	}

	h, err := NewRuleHandler(repo, slog.Default(), WithBudgetRepo(budgets))
	require.NoError(t, err)
	fx.Handler = h
	return fx
}

// BudgetLists returns the rule ids the budget repository was asked about, in
// order — the effect a budget read leaves behind.
func (f *RuleRouteFixture) BudgetLists() []string { return f.budgetLists }

// BudgetResets returns the "<ruleID>/<unit>" pairs ResetBudget was called with.
func (f *RuleRouteFixture) BudgetResets() []string { return f.budgetResets }

// RuleIDs returns the ids currently in the repository, so a test can assert that
// a request created or deleted nothing.
func (f *RuleRouteFixture) RuleIDs() []string {
	out := make([]string, 0, len(f.repo.rules))
	for id := range f.repo.rules {
		out = append(out, string(id))
	}
	return out
}

// RuleStatus returns one rule's status, or "" when the rule is gone. ⭐ This is
// how "did that request approve anything?" is answered by effect: approve moves
// pending_approval → active and reject moves it → rejected, both through
// ruleRepo.Update.
func (f *RuleRouteFixture) RuleStatus(id string) string {
	r, ok := f.repo.rules[types.RuleID(id)]
	if !ok {
		return ""
	}
	return string(r.Status)
}

// Proposals returns the ids of rows that are proposals for another rule —
// propose's only observable effect is that it writes one.
func (f *RuleRouteFixture) Proposals() []string {
	var out []string
	for id, r := range f.repo.rules {
		if r != nil && r.ProposalFor != nil {
			out = append(out, string(id))
		}
	}
	return out
}

// RuleRouteProposeBody is a proposal body that changes one field, so propose
// gets past its "at least one field must be changed" check and really writes.
func RuleRouteProposeBody() string {
	// ⚠️ description, not enabled: proposeRule's "at least one field must be
	// changed" check lists the proposable fields explicitly and `enabled` is not
	// one of them.
	b, _ := json.Marshal(map[string]any{"description": "proposed by a route test"})
	return string(b)
}
