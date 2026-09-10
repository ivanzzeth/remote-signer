//go:build integration

package registry

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// reservedPlaceholders are injected by the daemon rather than declared by the
// template author, so a template may reference them without listing them.
var reservedPlaceholders = map[string]bool{
	"chain_id": true,
}

var placeholderRe = regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)\}`)

// TestShippedTemplates_NoUndeclaredPlaceholders is a spending-limit check, not
// a tidiness check.
//
// ⛔ An unresolved ${var} in a budget cap does not fail. SubstituteMeteringJSON
// replaces whatever is left over with -1, and -1 means "no limit" in all three
// cap fields:
//
//	max_total   ""/"-1" → EnforcesBudgetLimit returns false
//	max_per_tx  same
//	max_tx_count  the SQL guard is `max_tx_count <= 0 OR tx_count < max_tx_count`
//
// So a template that references ${max_natve_total} — one letter off — ships a
// rule whose spending cap is silently unlimited, and nothing anywhere reports
// it. rules/templates/evm/agent.yaml alone has six caps written this way, and
// it is the template agents actually run under.
//
// The catalogue is clean today; this test is what keeps a typo from being the
// difference between a capped agent and an uncapped one.
func TestShippedTemplates_NoUndeclaredPlaceholders(t *testing.T) {
	root := findRepoRoot(t)
	rulesDir := filepath.Join(root, "rules")
	if _, err := os.Stat(rulesDir); err != nil {
		t.Skipf("rules/ not found at %s", rulesDir)
	}

	var offenders []string
	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative test fixture
		if err != nil {
			return err
		}

		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil // parse failures are another test's business
		}

		declared := declaredVariableNames(doc)
		rel, _ := filepath.Rel(root, path)

		// ⚠️ Scans the parsed values, not the raw bytes. Three preset files
		// document the feature in a comment — "All fields support ${var}" —
		// and a raw scan reports that as an undeclared variable.
		seen := map[string]bool{}
		for _, used := range placeholdersInValues(doc) {
			if seen[used] || declared[used] || reservedPlaceholders[used] {
				continue
			}
			seen[used] = true
			offenders = append(offenders, rel+": ${"+used+"}")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk rules/: %v", err)
	}

	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("placeholders referenced but never declared — an unresolved one in a budget cap becomes -1, which means unlimited:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// placeholdersInValues returns every ${name} appearing in a string value of the
// document, ignoring comments and keys.
func placeholdersInValues(o any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			for _, m := range placeholderRe.FindAllStringSubmatch(t, -1) {
				out = append(out, m[1])
			}
		case map[string]any:
			for _, val := range t {
				walk(val)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(o)
	return out
}

// declaredVariableNames collects every variable name a file declares, from
// `variables:` at any depth (templates declare at the top level, presets inside
// their own blocks) plus the keys of a preset's `variables:` mapping.
func declaredVariableNames(doc any) map[string]bool {
	out := map[string]bool{}
	var walk func(any)
	walk = func(o any) {
		switch v := o.(type) {
		case map[string]any:
			for k, val := range v {
				if k == "variables" {
					switch vars := val.(type) {
					case []any: // template form: a list of declarations
						for _, item := range vars {
							if m, ok := item.(map[string]any); ok {
								if name, ok := m["name"].(string); ok {
									out[name] = true
								}
							}
						}
					case map[string]any: // preset form: name -> value
						for name := range vars {
							out[name] = true
						}
					}
				}
				// matrix rows and operator_overrides bind names too.
				// test_variables binds names for offline test cases only, but
				// they are real bindings — a test case referencing one is not
				// an undeclared placeholder.
				if k == "test_variables" {
					if vars, ok := val.(map[string]any); ok {
						for name := range vars {
							out[name] = true
						}
					}
				}
				if k == "matrix" {
					if rows, ok := val.([]any); ok {
						for _, row := range rows {
							if m, ok := row.(map[string]any); ok {
								for name := range m {
									out[name] = true
								}
							}
						}
					}
				}
				if k == "operator_overrides" {
					if items, ok := val.([]any); ok {
						for _, item := range items {
							if m, ok := item.(map[string]any); ok {
								if name, ok := m["name"].(string); ok {
									out[name] = true
								}
							}
						}
					}
				}
				walk(val)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(doc)
	return out
}
