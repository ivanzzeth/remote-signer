//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/templates"
)

// getSignerPassword returns the unlock password for the signer used in
// the active e2e environment, or "" if unset. External-server runs
// configure this via E2E_SIGNER_PASSWORD; internal-server runs don't
// need it (the test signer is loaded via E2E_TEST_SIGNER_KEY directly
// and stays unlocked).
func getSignerPassword() string {
	return os.Getenv("E2E_SIGNER_PASSWORD")
}

// TestBundleTemplate_RoundTrip pins the path that broke in production
// when the file-based template registry forgot to detect bundle
// templates (top-level `rules:` in YAML).
//
// Bug symptoms: a freshly-loaded bundle template had `type==""` and no
// `config.rules_json`, so the template service's bundle dispatch was
// never entered. CreateInstance fell into the single-rule branch and
// stored a rule with `type==""`. The whitelist engine then warned
// "no evaluator for whitelist rule type, skipping" on every evaluation,
// silently routing every sign request to manual approval — even though
// the operator had applied the preset and the rule list looked fine
// in the API output.
//
// The test creates a bundle template via API (mimicking what the
// registry should produce when it parses an `evm/agent.yaml`-style
// file), instantiates it through the templates endpoint, and asserts:
//
//	1. The created template advertises type="template_bundle".
//	2. The instantiated rule carries the SUB-RULE's type (not the
//	   bundle's type — that's the whole point of bundle expansion).
//	3. A personal_sign matching the rule's sign_type_filter is
//	   auto-approved (status=completed) — not silently queued for
//	   manual approval.
func TestBundleTemplate_RoundTrip(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Ensure the signer is unlocked. HD-wallet signers come up locked
	// by default; the e2e harness's seeded test signer is unlocked by
	// fixture (E2E_TEST_SIGNER_KEY env), but when an external server
	// is used the operator may have provisioned a real signer
	// (keystore/hd-wallet) that needs explicit unlock. Best-effort:
	// the password env var lets us auto-unlock; if absent we proceed
	// and let the sign call surface a clear error.
	if pw := getSignerPassword(); pw != "" {
		_, _ = adminClient.EVM.Signers.Unlock(ctx, signerAddress, &evm.UnlockSignerRequest{Password: pw})
	}

	// 1. Create a bundle template. Mimics the YAML shape file_source.go
	// produces: a top-level `rules:` array whose entries each have
	// their own type/mode. The legacy single-rule shape (Config holds
	// the evaluator-config map directly) is exercised in
	// e2e_template_test.go; this test specifically covers the bundle
	// dispatch.
	subRule := map[string]interface{}{
		"id":      "bundle-sub",
		"name":    "Bundle Sub-Rule",
		"type":    "evm_js",
		"mode":    "whitelist",
		"enabled": true,
		"config": map[string]interface{}{
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
	}
	rulesJSON, err := json.Marshal([]interface{}{subRule})
	require.NoError(t, err)

	// The bundle template MUST have type="template_bundle" AND
	// config.rules_json (a JSON-encoded STRING, not an object array).
	// The registry's file loader produces this shape post-fix; here we
	// construct it directly via API so the test doesn't depend on file
	// I/O.
	tmplReq := &templates.CreateRequest{
		Name:        "Bundle Template Roundtrip",
		Description: "Test bundle template with sub-rules",
		Type:        "template_bundle",
		Mode:        "whitelist",
		Variables: []templates.TemplateVariable{
			{Name: "dummy", Type: "string", Description: "Unused", Required: false, Default: json.RawMessage(`"x"`)},
		},
		Config: map[string]interface{}{
			"rules_json": string(rulesJSON),
		},
		Enabled: true,
	}
	createdTmpl, err := adminClient.Templates.Create(ctx, tmplReq)
	require.NoError(t, err)
	require.NotNil(t, createdTmpl)
	defer func() {
		_ = adminClient.Templates.Delete(ctx, createdTmpl.ID)
	}()

	// Wire-level invariants the registry has to satisfy for bundle
	// expansion to fire downstream.
	assert.Equal(t, "template_bundle", createdTmpl.Type,
		"bundle template MUST advertise type=\"template_bundle\" — without this CreateInstance falls into the single-rule branch")
	require.NotEmpty(t, createdTmpl.Config, "bundle template MUST expose config including rules_json")
	var cfgCheck map[string]any
	require.NoError(t, json.Unmarshal(createdTmpl.Config, &cfgCheck))
	rulesJSONField, ok := cfgCheck["rules_json"].(string)
	require.True(t, ok, "bundle template MUST expose rules_json as a STRING (the instantiator's wire shape)")
	require.NotEmpty(t, rulesJSONField)

	// 2. Instantiate via the template API. The bundle dispatch should
	// expand the single sub-rule into one rule with type=evm_js.
	chainType := "evm"
	instReq := &templates.InstantiateRequest{
		Name:      "Bundle Template Roundtrip — Instance",
		Variables: map[string]string{"dummy": "ignored"},
		ChainType: &chainType,
	}
	inst, err := adminClient.Templates.Instantiate(ctx, createdTmpl.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, inst)
	require.NotEmpty(t, inst.Rule, "instantiation must return at least the primary rule")

	// Decode the returned rule to inspect its type. The fix lives in
	// the engine's ability to find an evaluator for the *sub-rule's*
	// type — so the returned rule's type MUST be the sub-rule type,
	// not the bundle template's "template_bundle" (or empty).
	var instRule struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Mode string `json:"mode"`
	}
	require.NoError(t, json.Unmarshal(inst.Rule, &instRule))
	defer func() {
		_ = adminClient.EVM.Rules.Delete(ctx, instRule.ID)
	}()
	assert.Equal(t, "evm_js", instRule.Type,
		"instantiated rule MUST carry the SUB-RULE's type, not empty — empty type makes the engine skip evaluation entirely")
	assert.Equal(t, "whitelist", instRule.Mode)

	// 3. Fire a personal_sign and assert the rule auto-approves it.
	signResp, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"bundle-rule-must-auto-approve"}`),
	})
	require.NoError(t, err, "personal_sign should succeed — a matching whitelist rule must auto-approve the request")
	require.NotNil(t, signResp)
	assert.Equal(t, "completed", string(signResp.Status),
		"sign status MUST be 'completed' — anything else (pending/authorizing) means the rule engine skipped the rule")
	assert.NotEmpty(t, signResp.Signature)

	// And the request must be attributable to OUR rule, not somebody
	// else's whitelist that happened to also match.
	if signResp.RuleMatched != "" {
		assert.True(t,
			strings.EqualFold(signResp.RuleMatched, instRule.ID),
			"rule_matched_id should be the instantiated bundle sub-rule, got %q",
			signResp.RuleMatched,
		)
	}
}
