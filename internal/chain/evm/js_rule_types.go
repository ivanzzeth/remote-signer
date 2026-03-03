package evm

// RuleInput is the normalized input passed to JS rules (evm_js).
// Matches docs/architecture/js-rules-v5.md §5.
// Hashes/digests are computed in Go; rules receive this shape only.
type RuleInput struct {
	SignType string `json:"sign_type"` // "transaction" | "typed_data" | "personal_sign"
	ChainID  int64  `json:"chain_id"`
	Signer   string `json:"signer"` // checksum address

	Transaction  *RuleInputTransaction  `json:"transaction,omitempty"`
	TypedData    *RuleInputTypedData    `json:"typed_data,omitempty"`
	PersonalSign *RuleInputPersonalSign `json:"personal_sign,omitempty"`
}

// RuleInputTransaction is the transaction subset of RuleInput.
// From is REQUIRED; engine must populate when derivable.
type RuleInputTransaction struct {
	From     string `json:"from"`               // REQUIRED, checksum
	To       string `json:"to"`                 // empty for contract creation
	Value    string `json:"value"`              // hex
	Data     string `json:"data"`               // hex
	Gas      string `json:"gas,omitempty"`      // decimal string
	MethodID string `json:"methodId,omitempty"` // 4-byte hex selector
}

// RuleInputTypedData is the EIP-712 subset (standard shape).
type RuleInputTypedData struct {
	Types       map[string][]TypedDataField `json:"types"`
	PrimaryType string                       `json:"primaryType"`
	Domain      TypedDataDomain              `json:"domain"`
	Message     map[string]interface{}       `json:"message"`
}

// RuleInputPersonalSign is the EIP-191 personal sign subset.
type RuleInputPersonalSign struct {
	Message string `json:"message"`
}

// JSRuleValidateResult is the return shape of JS validate(input).
// Invalid return / throw / timeout → wrapper converts to { valid: false, reason: "..." }.
// Script may optionally return delegate_to to route delegation by payload (e.g. by inner to-address).
type JSRuleValidateResult struct {
	Valid      bool        `json:"valid"`
	Reason     string      `json:"reason,omitempty"`
	Payload    interface{} `json:"payload,omitempty"`
	DelegateTo string      `json:"delegate_to,omitempty"` // optional; overrides config.delegate_to when delegating
}

// JSRuleConfig holds per-rule config for evm_js (script + optional delegation).
// Variables are injected exclusively as config object; no string substitution.
type JSRuleConfig struct {
	// Script is the JS source; must define validate(input) returning { valid, reason?, payload? }.
	Script string `json:"script"`

	// SignTypeFilter restricts to sign types. For evm_js only: may be comma-separated
	// (e.g. "typed_data,transaction"); other rule types support a single value only.
	SignTypeFilter string `json:"sign_type_filter,omitempty"`

	// Delegation (optional)
	DelegateTo   string `json:"delegate_to,omitempty"`   // target rule ID
	DelegateMode string `json:"delegate_mode,omitempty"` // "single" | "per_item" (default "single")
	ItemsKey     string `json:"items_key,omitempty"`     // required for per_item; default "items"
	PayloadKey   string `json:"payload_key,omitempty"`   // optional for single
}
