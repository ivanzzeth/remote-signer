// Package rule implements rule engine, budget checking, and whitelist/blocklist evaluation.
// This file handles budget unit normalization, decimal conversion, and variable substitution.
package rule

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

// NormalizeBudgetUnit normalizes a budget unit string for consistent storage and lookup.
// Lowercases the string so address casing (0xA0b8 vs 0xa0b8) does not cause mismatches.
func NormalizeBudgetUnit(unit string) string {
	return strings.ToLower(unit)
}

// decimalToRaw converts a human-readable decimal string (e.g. "1000") with the given number of
// decimals to a raw big integer string (e.g. "1000000000" for decimals=6).
// Supports both integer and fractional inputs (e.g. "0.1" with decimals=18).
func decimalToRaw(humanStr string, decimals int) (string, error) {
	if humanStr == "" || humanStr == "-1" {
		return humanStr, nil
	}

	// Split on decimal point
	parts := strings.Split(humanStr, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("invalid decimal string %q: multiple decimal points", humanStr)
	}

	intPart := parts[0]
	fracPart := ""
	if len(parts) == 2 {
		fracPart = parts[1]
	}

	// Validate no negative
	if strings.HasPrefix(intPart, "-") {
		return "", fmt.Errorf("negative budget limit not allowed: %q", humanStr)
	}

	// Truncate or pad fractional part to exactly `decimals` digits
	if len(fracPart) > decimals {
		return "", fmt.Errorf("fractional part of %q exceeds %d decimals", humanStr, decimals)
	}
	fracPart = fracPart + strings.Repeat("0", decimals-len(fracPart))

	// Combine: intPart + fracPart (no decimal point) = raw value
	rawStr := intPart + fracPart

	// Validate it parses as a big integer
	z := new(big.Int)
	if _, ok := z.SetString(rawStr, 10); !ok {
		return "", fmt.Errorf("failed to parse %q as big integer", rawStr)
	}

	return z.String(), nil
}

// extractUnitBase extracts the base address from a unit string that may have a :suffix.
// e.g. "0xABC123...:approve" -> "0xABC123...", "native" -> "native"
func extractUnitBase(rawUnit string) string {
	if idx := strings.Index(rawUnit, ":"); idx >= 0 {
		return rawUnit[:idx]
	}
	return rawUnit
}

// SubstituteMeteringJSON replaces ${var} placeholders in raw BudgetMetering JSON bytes
// using the rule's bound variables. This allows template budget_metering to use
// template variables (e.g. ${max_native_total}) that get resolved per-instance at runtime.
// Substitution happens on the raw JSON string before unmarshal so that int fields like
// max_tx_count can be resolved from "${var}" to actual integers.
// Returns the substituted JSON bytes, or the original if no variables are provided.
func SubstituteMeteringJSON(meteringJSON []byte, variablesJSON []byte) ([]byte, error) {
	if len(meteringJSON) == 0 {
		return meteringJSON, nil
	}
	if len(variablesJSON) == 0 {
		return meteringJSON, unresolvedCapError(string(meteringJSON))
	}
	vars := variablesToStringMap(variablesJSON)
	if len(vars) == 0 {
		return meteringJSON, unresolvedCapError(string(meteringJSON))
	}
	// Same expansion the engine performs — see substitution.go. Metering JSON
	// carries the same placeholder forms as a rule config does, so it must
	// resolve them the same way; the bare-${k}-only loop this replaces left
	// ${first:x} and ${hex:x} in place, and the -1 fallback below then silently
	// turned them into "unlimited".
	s := ExpandPlaceholders(string(meteringJSON), vars)

	// ⛔ A spending cap that did not resolve must never continue as a value.
	// The -1 fallback below keeps the JSON parseable, and -1 is exactly the
	// value that means "no limit" in all three cap fields:
	//
	//	max_total / max_per_tx   EnforcesBudgetLimit("-1") == false
	//	max_tx_count             the SQL guard is
	//	                         `max_tx_count <= 0 OR tx_count < max_tx_count`
	//
	// so a template referencing ${max_natve_total} — one letter off — shipped a
	// rule whose cap was silently unlimited, with nothing reporting it. The
	// engine already treats a budget-check error as fail-closed, so returning
	// one here turns a silent uncapped rule into a blocked request.
	//
	// ⚠️ Only the cap fields. decimals, alert_pct and param_index are not
	// limits, and -1 remains the right "unset" for them.
	if err := unresolvedCapError(s); err != nil {
		return nil, err
	}

	// Any remaining unresolved ${...} is in a non-cap field; -1 keeps the JSON
	// valid and reads as "unset" there.
	s = replaceRemainingPlaceholders(s)
	// Fix quoted integers: When a template has e.g. max_tx_count: ${var} in YAML,
	// it becomes "max_tx_count":"50" in JSON after substitution. For int fields,
	// JSON unmarshal expects unquoted numbers. Detect and fix this pattern.
	// We look for "field_name":"<digits>" where field is an int type.
	s = unquoteIntFields(s, []string{"max_tx_count", "decimals", "alert_pct", "max_dynamic_units", "param_index"})
	return []byte(s), nil
}

// capFieldPlaceholder matches a spending-cap field whose value still carries a
// ${...} — i.e. a limit nobody resolved.
var capFieldPlaceholder = regexp.MustCompile(`"(max_total|max_per_tx|max_tx_count)"\s*:\s*"?[^",}]*\$\{([^}]+)\}`)

// unresolvedCapError reports the cap fields in s that still hold a placeholder.
func unresolvedCapError(s string) error {
	matches := capFieldPlaceholder.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var parts []string
	for _, m := range matches {
		key := m[1] + "=${" + m[2] + "}"
		if seen[key] {
			continue
		}
		seen[key] = true
		parts = append(parts, key)
	}
	sort.Strings(parts)
	return fmt.Errorf("budget cap left unresolved (%s): an unresolved cap would read as unlimited", strings.Join(parts, ", "))
}

// unquoteIntFields replaces "field":"<digits>" with "field":<digits> in JSON for
// fields that expect integer values. This handles the case where ${var} substitution
// produces a quoted number string that needs to be an unquoted JSON integer.
func unquoteIntFields(jsonStr string, fields []string) string {
	for _, field := range fields {
		// Match "field":"digits" or "field": "digits" (with optional whitespace after colon)
		// and replace with "field":digits (preserving original spacing)
		for _, sep := range []string{`":"`, `": "`} {
			prefix := `"` + field + sep
			colonSep := sep[:len(sep)-1] // `":` or `": ` — everything before the opening quote of value
			for {
				idx := strings.Index(jsonStr, prefix)
				if idx < 0 {
					break
				}
				valueStart := idx + len(prefix)
				endQuote := strings.Index(jsonStr[valueStart:], `"`)
				if endQuote < 0 {
					break
				}
				value := jsonStr[valueStart : valueStart+endQuote]
				trimmed := strings.TrimSpace(value)
				if isIntegerString(trimmed) {
					oldStr := prefix + value + `"`
					newStr := `"` + field + colonSep + trimmed
					jsonStr = strings.Replace(jsonStr, oldStr, newStr, 1)
				} else {
					break
				}
			}
		}
	}
	return jsonStr
}

func replaceRemainingPlaceholders(s string) string {
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			return s
		}
		end := strings.Index(s[start:], "}")
		if end < 0 {
			return s
		}
		s = s[:start] + "-1" + s[start+end+1:]
	}
}

// isIntegerString returns true if s is a valid integer (optionally negative).
func isIntegerString(s string) bool {
	if s == "" {
		return false
	}
	start := 0
	if s[0] == '-' {
		start = 1
	}
	if start >= len(s) {
		return false
	}
	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// variablesToStringMap parses rule.Variables JSON into a string map.
func variablesToStringMap(variablesJSON []byte) map[string]string {
	if len(variablesJSON) == 0 {
		return nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(variablesJSON, &raw); err != nil || len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if v == nil {
			continue
		}
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s != "" {
			out[k] = s
		}
	}
	return out
}

// substituteUnitVariables replaces ${var} in unit using rule.Variables so the unit matches
// the budget record created at sync (e.g. "${chain_id}:${token_address}" -> "1:0xA0b8...").
// Uses interface{} unmarshal so number values (e.g. chain_id: 1 from YAML) are converted to string.
func substituteUnitVariables(unit string, variablesJSON []byte) string {
	if unit == "" || len(variablesJSON) == 0 {
		return unit
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(variablesJSON, &raw); err != nil || len(raw) == 0 {
		return unit
	}
	strVars := make(map[string]string, len(raw))
	for k, v := range raw {
		if v == nil {
			continue
		}
		strVars[k] = fmt.Sprintf("%v", v)
	}
	// A budget unit is a key other rows are matched against — "1:0xA0b8…" — so
	// an unexpanded ${token_address} here means spend lands on a different row
	// than the limit it should be checked against.
	return ExpandPlaceholders(unit, strVars)
}
