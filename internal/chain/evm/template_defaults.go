package evm

import (
	"context"
	"encoding/json"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// templateVariableDefs maps template ID → variable definitions (with defaults).
// Populated at server startup from the template repository.
var templateVariableDefs map[string][]types.TemplateVariable

// SetTemplateVariableDefs installs the template-default lookup table used when
// resolving instance rule Variables at evaluation time.
func SetTemplateVariableDefs(defs map[string][]types.TemplateVariable) {
	templateVariableDefs = defs
}

// LoadTemplateVariableDefs reads all templates from repo and builds the lookup
// table for runtime default resolution.
func LoadTemplateVariableDefs(ctx context.Context, repo storage.TemplateRepository) error {
	templates, err := repo.List(ctx, storage.TemplateFilter{Limit: 10000})
	if err != nil {
		return err
	}
	defs := make(map[string][]types.TemplateVariable, len(templates))
	for _, tmpl := range templates {
		if tmpl == nil || len(tmpl.Variables) == 0 {
			continue
		}
		var varDefs []types.TemplateVariable
		if err := json.Unmarshal(tmpl.Variables, &varDefs); err != nil {
			continue
		}
		defs[tmpl.ID] = varDefs
	}
	SetTemplateVariableDefs(defs)
	return nil
}

func templateDefsForRule(r *types.Rule) []types.TemplateVariable {
	if r == nil || r.TemplateID == nil || templateVariableDefs == nil {
		return nil
	}
	return templateVariableDefs[*r.TemplateID]
}

func applyTemplateDefaultsToStringMap(r *types.Rule, vars map[string]string) map[string]string {
	defs := templateDefsForRule(r)
	if len(defs) == 0 {
		return vars
	}
	return rule.ApplyVariableDefaults(defs, vars)
}
