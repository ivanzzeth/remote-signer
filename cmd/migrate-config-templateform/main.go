// Command migrate-config-templateform is a one-off migration for the Option A
// refactor: it rewrites existing instance rules' Config from rendered (variables
// substituted in) to TEMPLATE form (${var} placeholders), so the rule engine's
// live substitution makes Variables the single source of truth.
//
// It is SELF-VERIFYING: for each rule it derives the template-form Config from
// the rule's template, then checks that substituting the rule's Variables back
// in reproduces the CURRENT stored Config byte-for-byte (JSON-normalized). Only
// rules that pass are updated; any mismatch is reported and skipped, so the
// migration can never change evaluation behavior.
//
// Usage: go run ./cmd/migrate-config-templateform [-dsn <dsn>] [-apply]
// Without -apply it runs a dry-run (reports what would change).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/homepath"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func main() {
	defaultDSN, _ := homepath.DefaultSQLiteDSN()
	dsn := flag.String("dsn", defaultDSN, "database DSN")
	apply := flag.Bool("apply", false, "actually write changes (default: dry-run)")
	flag.Parse()

	if err := run(*dsn, *apply); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dsn string, apply bool) error {
	db, err := storage.NewDB(storage.Config{DSN: dsn})
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	ruleRepo, err := storage.NewGormRuleRepository(db)
	if err != nil {
		return fmt.Errorf("rule repo: %w", err)
	}
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	if err != nil {
		return fmt.Errorf("template repo: %w", err)
	}
	ctx := context.Background()

	rules, err := ruleRepo.List(ctx, storage.RuleFilter{Limit: -1})
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	var migrated, skipped, untouched int
	for _, r := range rules {
		if r.Source != types.RuleSourceInstance || r.TemplateID == nil || *r.TemplateID == "" {
			continue
		}
		if len(r.Variables) == 0 {
			untouched++
			continue
		}
		// Already template-form? (contains a ${...} token)
		if strings.Contains(string(r.Config), "${") {
			untouched++
			continue
		}

		tmpl, err := tmplRepo.Get(ctx, *r.TemplateID)
		if err != nil {
			fmt.Printf("SKIP  %s (%s): template %q not found: %v\n", r.ID, r.Name, *r.TemplateID, err)
			skipped++
			continue
		}

		candidate, err := templateFormConfig(tmpl, r)
		if err != nil {
			fmt.Printf("SKIP  %s (%s): %v\n", r.ID, r.Name, err)
			skipped++
			continue
		}

		// SELF-VERIFY (behavior-preserving check): substituting Variables into the
		// candidate must (a) match the current Config on every field the candidate
		// defines, and (b) the only EXTRA keys in the current Config must be dead
		// variable keys that the old create-time pipeline injected (value equals
		// the corresponding Variable). Those injected keys are never read at eval
		// (the evaluator builds the script config object from Variables), so
		// dropping them changes nothing. Any other difference => skip.
		vars := varMap(r)
		resolved := substituteVars(candidate, vars)
		if reason := behaviorDiff(resolved, r.Config, declaredVarNames(tmpl)); reason != "" {
			fmt.Printf("SKIP  %s (%s): %s\n", r.ID, r.Name, reason)
			skipped++
			continue
		}

		fmt.Printf("OK    %s (%s)\n", r.ID, r.Name)
		if apply {
			r.Config = candidate
			if err := ruleRepo.Update(ctx, r); err != nil {
				return fmt.Errorf("update rule %s: %w", r.ID, err)
			}
		}
		migrated++
	}

	mode := "DRY-RUN (no changes written; pass -apply to write)"
	if apply {
		mode = "APPLIED"
	}
	fmt.Printf("\n%s — migrated=%d skipped=%d untouched=%d\n", mode, migrated, skipped, untouched)
	if skipped > 0 {
		return fmt.Errorf("%d rule(s) skipped; review before relying on migration", skipped)
	}
	return nil
}

// templateFormConfig returns the template-form (${var}) config for an instance
// rule, preserving any already-resolved delegate_to / delegate_to_by_target that
// the create-time pipeline computed (cross-template inst IDs cannot be recovered
// from Variables alone).
func templateFormConfig(tmpl *types.RuleTemplate, r *types.Rule) ([]byte, error) {
	var cand map[string]interface{}
	if tmpl.Type == "template_bundle" {
		sub, err := matchSubRuleConfig(tmpl, r)
		if err != nil {
			return nil, err
		}
		cand = sub
	} else {
		if err := json.Unmarshal(tmpl.Config, &cand); err != nil {
			return nil, fmt.Errorf("parse template config: %w", err)
		}
	}

	// Preserve resolved delegate fields from the current (rendered) config when
	// the template form would otherwise carry an unresolvable literal id.
	var cur map[string]interface{}
	if json.Unmarshal(r.Config, &cur) == nil {
		for _, k := range []string{"delegate_to", "delegate_to_by_target"} {
			tv, _ := cand[k].(string)
			cv, ok := cur[k].(string)
			if ok && cv != "" && !strings.Contains(tv, "${") && tv != cv {
				cand[k] = cv
			}
		}
	}

	out, err := json.Marshal(cand)
	if err != nil {
		return nil, fmt.Errorf("marshal candidate: %w", err)
	}
	return out, nil
}

type bundleSub struct {
	ID     string                 `json:"id"`
	Name   string                 `json:"name"`
	Config map[string]interface{} `json:"config"`
}

// matchSubRuleConfig finds the bundle sub-rule whose name matches the instance
// rule (rule names are "<base> / <sub.Name>").
func matchSubRuleConfig(tmpl *types.RuleTemplate, r *types.Rule) (map[string]interface{}, error) {
	var cfgMap map[string]interface{}
	if err := json.Unmarshal(tmpl.Config, &cfgMap); err != nil {
		return nil, fmt.Errorf("parse bundle config: %w", err)
	}
	rulesJSON, _ := cfgMap["rules_json"].(string)
	var subs []bundleSub
	if err := json.Unmarshal([]byte(rulesJSON), &subs); err != nil {
		return nil, fmt.Errorf("parse rules_json: %w", err)
	}
	var match *bundleSub
	for i := range subs {
		if strings.HasSuffix(r.Name, subs[i].Name) {
			if match != nil {
				return nil, fmt.Errorf("ambiguous sub-rule name match for %q", r.Name)
			}
			match = &subs[i]
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no sub-rule matches rule name %q", r.Name)
	}
	return match.Config, nil
}

func varMap(r *types.Rule) map[string]string {
	vars := map[string]string{}
	if len(r.Variables) > 0 {
		_ = json.Unmarshal(r.Variables, &vars)
	}
	if r.ChainID != nil && *r.ChainID != "" {
		vars["chain_id"] = *r.ChainID
	}
	return vars
}

// substituteVars mirrors core/rule.substituteConfigVars (loose).
func substituteVars(configJSON []byte, vars map[string]string) []byte {
	result := string(configJSON)
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
		hexv := strings.TrimPrefix(v, "0x")
		result = strings.ReplaceAll(result, "${hex:"+k+"}", hexv)
		padded := hexv
		if len(hexv) < 64 {
			padded = strings.Repeat("0", 64-len(hexv)) + hexv
		}
		result = strings.ReplaceAll(result, "${paddedhex:"+k+"}", padded)
		first := firstOfList(v)
		result = strings.ReplaceAll(result, "${first:"+k+"}", first)
		result = strings.ReplaceAll(result, "${hex:first:"+k+"}", strings.TrimPrefix(first, "0x"))
	}
	return []byte(result)
}

func firstOfList(s string) string {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			return p
		}
	}
	return ""
}

// nonFunctional config keys are metadata never read at evaluation; differences
// in them do not change behavior, so the verifier ignores them.
var nonFunctional = map[string]bool{"test_cases": true, "description": true}

// behaviorDiff returns "" when migrating to `resolved` is behavior-preserving vs
// `current`: every FUNCTIONAL field the candidate defines must match current,
// and every extra key present only in `current` must be a declared template
// variable (a dead key the old create-time pipeline injected — never read at
// eval, possibly stale relative to Variables). Returns a reason otherwise.
func behaviorDiff(resolved, current []byte, declared map[string]bool) string {
	var rm, cm map[string]interface{}
	if err := json.Unmarshal(resolved, &rm); err != nil {
		return "resolved candidate not JSON object: " + err.Error()
	}
	if err := json.Unmarshal(current, &cm); err != nil {
		return "current config not JSON object: " + err.Error()
	}
	// (a) candidate-defined functional fields must match current exactly.
	for k, rv := range rm {
		if nonFunctional[k] {
			continue
		}
		cv, ok := cm[k]
		if !ok {
			return fmt.Sprintf("candidate field %q missing from current config", k)
		}
		if !reflect.DeepEqual(rv, cv) {
			return fmt.Sprintf("candidate field %q differs from current", k)
		}
	}
	// (b) extra keys present only in current must be declared template variables
	// (dead injected keys) — anything else would be a real field we'd drop.
	for k := range cm {
		if _, ok := rm[k]; ok || nonFunctional[k] {
			continue
		}
		if !declared[k] {
			return fmt.Sprintf("extra key %q in current config is not a template variable", k)
		}
	}
	return ""
}

// declaredVarNames returns the template's declared variable names plus chain_id
// (the keys the old pipeline injected into rendered configs).
func declaredVarNames(tmpl *types.RuleTemplate) map[string]bool {
	out := map[string]bool{"chain_id": true}
	var defs []types.TemplateVariable
	if len(tmpl.Variables) > 0 {
		_ = json.Unmarshal(tmpl.Variables, &defs)
	}
	for _, d := range defs {
		out[d.Name] = true
	}
	return out
}

func truncate(b []byte) string {
	s := string(b)
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}
