//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// TestRule_TypeFieldIsExposedInAPI locks the contract that rule.type
// MUST round-trip through Create → Get → List. (P2 #9 in
// MISSING_COVERAGE.md.)
//
// Why this exists: the bundle-template bug landed because rules with
// `type=""` looked fine in the database but the engine had no evaluator
// for them and silently skipped every evaluation. If the API
// serializer ever drops the type field, the bug regresses invisibly —
// the engine still tries to load it server-side and skips, while the
// rule list / get views lie that everything is fine. The test asserts
// the field is non-empty on every read path.
func TestRule_TypeFieldIsExposedInAPI(t *testing.T) {
	ctx := context.Background()
	req := &evm.CreateRuleRequest{
		Name:    "Rule Type Field Roundtrip",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
		},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, req)
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, created.ID) }()

	// The Create response itself MUST surface the type.
	assert.Equal(t, "evm_address_list", created.Type,
		"Create response MUST echo rule.type — the engine relies on this field to pick an evaluator")
	assert.Equal(t, "whitelist", created.Mode,
		"Create response MUST echo rule.mode")

	// Get-by-id MUST also surface the type.
	got, err := adminClient.EVM.Rules.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "evm_address_list", got.Type,
		"Get response MUST surface rule.type — empty here would mask the exact bug we hit with bundle templates")
	assert.Equal(t, "whitelist", got.Mode)

	// List MUST also surface the type. Find our row in the page.
	listResp, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	var found *evm.Rule
	for i, r := range listResp.Rules {
		if r.ID == created.ID {
			found = &listResp.Rules[i]
			break
		}
	}
	require.NotNil(t, found, "freshly-created rule MUST appear in the list within the default page")
	assert.Equal(t, "evm_address_list", found.Type,
		"List response MUST surface rule.type for every row — operators read this to debug 'why isn't my rule matching?'")
	assert.NotEmpty(t, found.Mode, "List response MUST surface rule.mode for every row")
}

// TestRule_TypeRoundTripsToEngine is P0 #3 in MISSING_COVERAGE.md: it
// closes the loop from "rule created via API with explicit type" all
// the way to "engine actually evaluates the rule and auto-approves a
// matching sign". A regression that stores rule.type="" on the way to
// the engine — exactly what the bundle bug did — would fail here at
// the "completed" assertion: the engine logs "no evaluator… skipping"
// and the sign falls through to manual approval.
func TestRule_TypeRoundTripsToEngine(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	req := &evm.CreateRuleRequest{
		Name:    "Rule Type Engine Roundtrip",
		Type:    "evm_js",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"sign_type_filter": "personal_sign",
			"script": `
				function validate(input) {
					if (input.sign_type === 'personal_sign') {
						return ok();
					}
					revert('unsupported sign type: ' + input.sign_type);
				}
				function validateBudget(input) {
					return { amount: 1n, unit: 'sign_count' };
				}
			`,
		},
		// evm_js validator requires at least one positive AND one
		// negative test case — pin the expected match shape inline.
		// TestCases is a top-level field on the API request, NOT
		// inside config.
		TestCases: []evm.JSRuleTestCase{
			{
				Name:       "personal_sign passes",
				Input:      map[string]interface{}{"sign_type": "personal_sign"},
				ExpectPass: true,
			},
			{
				Name:       "other sign type fails",
				Input:      map[string]interface{}{"sign_type": "eth_signTypedData_v4"},
				ExpectPass: false,
			},
		},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, req)
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, created.ID) }()
	require.Equal(t, "evm_js", created.Type, "precondition: rule must be created with type=evm_js")

	signResp, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"rule-type-roundtrip"}`),
	})
	require.NoError(t, err,
		"personal_sign MUST succeed — a matching whitelist rule must auto-approve. If this fails with 'pending', the rule.type was lost between API and engine.")
	require.NotNil(t, signResp)
	assert.Equal(t, "completed", string(signResp.Status),
		"sign status MUST be 'completed' — anything else means the engine couldn't find an evaluator for rule.type, i.e. the field was dropped on the way in")
	assert.NotEmpty(t, signResp.Signature)

	if signResp.RuleMatched != "" {
		assert.True(t,
			strings.EqualFold(signResp.RuleMatched, created.ID),
			"rule_matched_id should be the rule we just created, got %q (a different whitelist rule matched — test was supposed to verify OUR rule's evaluator wired up)",
			signResp.RuleMatched,
		)
	}

	// And the rule's match_count must reflect at least this one
	// invocation — proves the engine treats it as a live evaluator,
	// not a no-op skip. (Pairs with P1 #5 which expands this assertion
	// across all shipped presets.)
	afterSign, err := adminClient.EVM.Rules.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, afterSign.MatchCount, uint64(1),
		"rule.match_count MUST increment after a matching sign — 0 means the engine evaluated something else (or nothing)")
}
