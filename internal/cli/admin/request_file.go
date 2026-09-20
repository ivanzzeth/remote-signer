package admin

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// decodeRequestFile decodes a `--file` request body into an API request type.
//
// # Why this exists
//
// The API request types (templates.InstantiateRequest, evm.CreateRuleRequest,
// …) carry only `json:` tags, because that is the wire format. yaml.v3 does not
// look at those tags: with no `yaml:` tag it derives the key from the Go field
// name, lowercased and with nothing in between — MaxTotal becomes "maxtotal",
// ChainID becomes "chainid".
//
// So every key the API documents in snake_case bound to *nothing* and silently
// took the zero value. A budget written the documented way:
//
//	budget:
//	  max_total: "1000000000000000000"
//	  max_per_tx: "1000000000000000000"
//	  max_tx_count: 10000
//
// produced a budget row with empty limits and max_tx_count 0, and the rule then
// rejected every request with "budget exceeded" — which reads like a limit that
// is too low, not like a file that never applied. Nothing reported a problem at
// any point: the file parsed, the rule was created, the server answered 200.
//
// The same trap hit `--file` JSON, which the flag help advertises: JSON is a
// subset of YAML, so it parsed fine and its keys were dropped just the same.
//
// Routing through JSON makes the `json:` tags authoritative for both formats,
// which is what every caller already assumes from the API docs.
//
// # Unknown keys are an error
//
// The bug above is one instance of a class: a key that does not bind is
// indistinguishable from a key that was never written. Since the whole point of
// this helper is that a request file means what it says, a key that binds to
// nothing is reported rather than dropped — a typo in `max_per_tx` must not be
// the difference between a budget and no budget.
func decodeRequestFile(data []byte, v any) error {
	// yaml.v3 decodes mappings into map[string]any when the target is `any`
	// (unlike yaml.v2's map[any]any), so this re-encodes cleanly.
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse request file: %w", err)
	}
	if doc == nil {
		return fmt.Errorf("parse request file: it is empty")
	}
	j, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("parse request file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("parse request file: %w", err)
	}
	return nil
}
