package service

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Typed variable substitution
//
// The pre-R5 substituter (SubstituteVariables) treated every variable as
// a string and did naive string replace into the template config JSON.
// That collapsed two distinct shapes into one:
//
//   - "to": "${addr}"             — inline string substitution into a
//                                   JSON string. Wants quotes preserved.
//   - "addresses": "${addr_list}" — placeholder *is* the whole value.
//                                   Wants quotes replaced so an array
//                                   literal can take its place.
//
// SubstituteTyped distinguishes the two by checking whether the
// placeholder appears as `"${var}"` (whole-string position — replaceable
// with any JSON value, including arrays/bools) or as `${var}` inside a
// larger string (inline — only strings make sense here). Lists, bools,
// and json variables are required to be in whole-string position; using
// them inline returns an error rather than producing malformed JSON.
//
// The substituter doesn't reach into chain-format details (no EVM
// address checksum re-encoding, no big-int range check). That's the
// validator's job — by the time values reach this function they've
// already been resolved by ResolveAndValidateTyped.

// SubstituteTyped substitutes ${var} placeholders in configJSON using
// typed values from vars. defs supplies the variable shape so the
// substituter knows when to peel surrounding quotes (lists/bools/json)
// vs do an inline string splice (string/address/bigint/duration/etc.).
//
// Returns an error for: unresolved placeholders, non-string types in
// inline position, and any value that cannot be JSON-encoded.
func SubstituteTyped(configJSON []byte, defs []types.TemplateVariable, vars map[string]any) ([]byte, error) {
	if len(configJSON) == 0 {
		return configJSON, nil
	}

	defByName := make(map[string]types.TemplateVariable, len(defs))
	for _, d := range defs {
		defByName[d.Name] = d
	}

	result := string(configJSON)
	for name, raw := range vars {
		def, ok := defByName[name]
		// Reserved vars (e.g. chain_id) are not in defs but still
		// substitutable. Treat them as strings.
		varType := types.VarTypeString
		if ok {
			varType = def.Type
		}

		quoted := `"${` + name + `}"`
		inline := `${` + name + `}`

		if strings.Contains(result, quoted) {
			enc, err := jsonEncodeTyped(name, varType, raw)
			if err != nil {
				return nil, err
			}
			result = strings.ReplaceAll(result, quoted, enc)
		}

		if strings.Contains(result, inline) {
			if !inlineCompatible(varType) {
				return nil, fmt.Errorf("variable %q (type %s) cannot be used inline; use whole-value position \"${%s}\"", name, varType, name)
			}
			s, err := inlineStringForm(name, varType, raw)
			if err != nil {
				return nil, err
			}
			result = strings.ReplaceAll(result, inline, s)
		}
	}

	if rest := findUnresolvedVars(result); len(rest) > 0 {
		return nil, fmt.Errorf("unresolved variables: %s", strings.Join(rest, ", "))
	}

	return []byte(result), nil
}

// inlineCompatible reports whether a type can be spliced inside another
// JSON string (e.g. used in a URL or message template). Anything that
// would render as non-string JSON (arrays, bools, raw json) is rejected
// in inline position; the operator must use the whole-value form.
func inlineCompatible(t types.VariableType) bool {
	switch t {
	case types.VarTypeAddress,
		types.VarTypeBigInt,
		types.VarTypeString,
		types.VarTypeBytes,
		types.VarTypeBytes4,
		types.VarTypeDuration,
		types.VarTypeEnum:
		return true
	}
	return false
}

// jsonEncodeTyped renders a value as the JSON literal that should
// replace the quoted placeholder. For string-shaped types it returns
// the quoted JSON string ("0xabc"). For arrays/bools/json it returns
// the natural JSON form ([..], true, {..}). Numeric values (bigint)
// stay JSON-string-encoded — wide integers can't survive a JSON number
// round-trip through downstream consumers.
func jsonEncodeTyped(name string, t types.VariableType, raw any) (string, error) {
	switch t {
	case types.VarTypeBool:
		b, err := asBool(name, raw)
		if err != nil {
			return "", err
		}
		if b {
			return "true", nil
		}
		return "false", nil

	case types.VarTypeAddressList, types.VarTypeBigIntList:
		items, err := asStringSlice(name, raw)
		if err != nil {
			return "", err
		}
		out, err := json.Marshal(items)
		if err != nil {
			return "", fmt.Errorf("variable %q: encode list: %w", name, err)
		}
		return string(out), nil

	case types.VarTypeJSON:
		// JSON variables already carry structured content. Marshal as-is
		// so the operator can pass a map / list / scalar through.
		out, err := json.Marshal(raw)
		if err != nil {
			return "", fmt.Errorf("variable %q: encode json: %w", name, err)
		}
		return string(out), nil

	case types.VarTypeBigInt:
		s, err := asBigIntString(name, raw)
		if err != nil {
			return "", err
		}
		out, err := json.Marshal(s)
		if err != nil {
			return "", err
		}
		return string(out), nil

	case types.VarTypeDuration:
		s, err := asDurationString(name, raw)
		if err != nil {
			return "", err
		}
		out, err := json.Marshal(s)
		if err != nil {
			return "", err
		}
		return string(out), nil

	case types.VarTypeAddress, types.VarTypeString, types.VarTypeBytes,
		types.VarTypeBytes4, types.VarTypeEnum:
		s, err := asString(name, raw)
		if err != nil {
			return "", err
		}
		out, err := json.Marshal(s)
		if err != nil {
			return "", err
		}
		return string(out), nil
	}
	return "", fmt.Errorf("variable %q: unknown type %s", name, t)
}

// inlineStringForm returns the bare characters that should be spliced
// into a surrounding JSON string. Standard JSON-escape via json.Marshal,
// then strip the wrapping quotes — that gives us correct escaping of
// embedded quotes / backslashes / control chars without re-implementing
// the escape table.
func inlineStringForm(name string, t types.VariableType, raw any) (string, error) {
	var s string
	var err error
	switch t {
	case types.VarTypeBigInt:
		s, err = asBigIntString(name, raw)
	case types.VarTypeDuration:
		s, err = asDurationString(name, raw)
	default:
		s, err = asString(name, raw)
	}
	if err != nil {
		return "", err
	}
	enc, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	// Trim the surrounding quotes — we're splicing into an existing
	// JSON string, not replacing one.
	return string(enc[1 : len(enc)-1]), nil
}

// ---------------------------------------------------------------------------
// Type coercion helpers
// ---------------------------------------------------------------------------
//
// The substituter accepts loose input (so YAML round-trip and HTTP
// request bodies don't have to pre-coerce) and converts at substitution
// time. Each helper centralises one type's quirks.

func asString(name string, v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case fmt.Stringer:
		return x.String(), nil
	case int, int32, int64, uint, uint32, uint64, float32, float64:
		return fmt.Sprintf("%v", x), nil
	case bool:
		return strconv.FormatBool(x), nil
	case nil:
		return "", nil
	}
	return "", fmt.Errorf("variable %q: cannot coerce %T to string", name, v)
}

func asBool(name string, v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		b, err := strconv.ParseBool(x)
		if err != nil {
			return false, fmt.Errorf("variable %q: %q is not a bool", name, x)
		}
		return b, nil
	}
	return false, fmt.Errorf("variable %q: cannot coerce %T to bool", name, v)
}

func asStringSlice(name string, v any) ([]string, error) {
	switch x := v.(type) {
	case []string:
		return x, nil
	case []any:
		out := make([]string, 0, len(x))
		for i, e := range x {
			s, err := asString(name+fmt.Sprintf("[%d]", i), e)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	case string:
		// Legacy: comma-separated. Trim each entry; drop blanks. Keeps
		// presets written before the YAML migration working when the
		// operator hand-edits "a,b,c" into a *_list slot.
		parts := strings.Split(x, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out, nil
	case nil:
		return nil, nil
	}
	return nil, fmt.Errorf("variable %q: cannot coerce %T to []string", name, v)
}

// asBigIntString validates that the value parses as a base-10 big int
// (or is the sentinel "-1" used by some rules to mean "unlimited") and
// returns its canonical string form. Wide integers stay in string form
// throughout the pipeline; never reduced to int64.
func asBigIntString(name string, v any) (string, error) {
	s, err := asString(name, v)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", fmt.Errorf("variable %q: bigint cannot be empty", name)
	}
	if s == "-1" {
		return s, nil
	}
	bi := new(big.Int)
	if _, ok := bi.SetString(s, 10); !ok {
		return "", fmt.Errorf("variable %q: invalid bigint %q", name, s)
	}
	return bi.String(), nil
}

func asDurationString(name string, v any) (string, error) {
	s, err := asString(name, v)
	if err != nil {
		return "", err
	}
	if _, err := time.ParseDuration(s); err != nil {
		return "", fmt.Errorf("variable %q: invalid duration %q: %w", name, s, err)
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// Unresolved-placeholder scan
// ---------------------------------------------------------------------------

var placeholderRE = regexp.MustCompile(`\$\{([^}]+)\}`)

func findUnresolvedVars(s string) []string {
	matches := placeholderRE.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	var out []string
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}
