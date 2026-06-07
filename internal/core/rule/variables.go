package rule

import (
	"encoding/json"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// MergeVariablesMap overlays patch onto base. Keys in patch replace or add;
// keys only in base are preserved.
func MergeVariablesMap(base, patch map[string]string) map[string]string {
	if len(base) == 0 && len(patch) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(base)+len(patch))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range patch {
		out[k] = v
	}
	return out
}

// MergeVariablesJSON unmarshals base and patch JSON objects (map[string]string),
// merges patch onto base, and returns the merged JSON. Nil or empty inputs are
// treated as empty maps.
func MergeVariablesJSON(base, patch []byte) ([]byte, error) {
	baseMap, err := decodeVariablesJSON(base)
	if err != nil {
		return nil, fmt.Errorf("decode base variables: %w", err)
	}
	patchMap, err := decodeVariablesJSON(patch)
	if err != nil {
		return nil, fmt.Errorf("decode patch variables: %w", err)
	}
	return json.Marshal(MergeVariablesMap(baseMap, patchMap))
}

func decodeVariablesJSON(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return map[string]string{}, nil
	}
	return m, nil
}

// ApplyVariableDefaults fills missing keys from template variable definitions.
// Provided values always win; defaults apply only when a key is absent.
func ApplyVariableDefaults(defs []types.TemplateVariable, vars map[string]string) map[string]string {
	if len(defs) == 0 {
		return vars
	}
	out := make(map[string]string, len(vars)+len(defs))
	for k, v := range vars {
		out[k] = v
	}
	for _, def := range defs {
		if _, provided := out[def.Name]; provided {
			continue
		}
		if def.Default == nil {
			continue
		}
		switch d := def.Default.(type) {
		case string:
			// Empty string is a legitimate default (e.g. token_address = any).
			out[def.Name] = d
		default:
			out[def.Name] = fmt.Sprint(d)
		}
	}
	return out
}
