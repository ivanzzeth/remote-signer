package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestUpdateRule_VariablesTakeEffectWithoutRerender verifies the Option A
// contract from the update side: editing an instance rule's Variables updates
// Variables only — the template-form Config is left untouched (no rendered
// snapshot), because the engine substitutes Variables live at evaluation. This
// is the regression guard for the original bug (adding a Safe to
// allowed_safe_addresses via the UI silently had no effect).
func TestUpdateRule_VariablesTakeEffectWithoutRerender(t *testing.T) {
	repo := newMockRuleRepo()

	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.Source = types.RuleSourceInstance
	rule.Type = types.RuleTypeEVMJS
	rule.TemplateID = strPtr("evm/safe_bundle")
	// Config is stored template-form (placeholders intact).
	const tmplForm = `{"script":"function validate(i){return ok();}","allowed_safe_addresses":"${allowed_safe_addresses}"}`
	rule.Config = json.RawMessage(tmplForm)
	rule.Variables = json.RawMessage(`{"allowed_safe_addresses":"0xOLD"}`)
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	newSafe := "0x8faE526C4cfE0b799003d2110F92C40499c6609f"
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{
			"variables": map[string]string{"allowed_safe_addresses": newSafe + ",0xOLD"},
		}, ruleAdminKey())
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	updated, err := repo.Get(context.Background(), rule.ID)
	require.NoError(t, err)

	// Config must remain template-form — the update does NOT render variables in.
	assert.JSONEq(t, tmplForm, string(updated.Config),
		"Config must stay template-form; the engine resolves Variables live")

	// Variables carry the new value — the single source of truth the engine reads.
	var vars map[string]string
	require.NoError(t, json.Unmarshal(updated.Variables, &vars))
	assert.Contains(t, vars["allowed_safe_addresses"], newSafe,
		"updated Variables must contain the new Safe")
}
