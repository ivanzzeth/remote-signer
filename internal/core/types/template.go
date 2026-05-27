package types

import "time"

// RuleTemplate represents a parameterized rule template with ${variable} placeholders.
// Templates define the rule logic (config) with variables, and instances bind concrete values.
//
// Identity: ID is the canonical key — for file-sourced templates the
// Registry sets it to the YAML file stem (e.g. "erc20"), giving operators
// a stable name to reference across reloads. Name is the friendly label
// the UI shows. ChainType narrows the template to one ledger family;
// empty means "chain-agnostic" (e.g. sign_type_allowlist).
//
// Provenance: Source / SourcePath / SourceRef tell the Registry where
// the row came from, and ContentHash lets Sync skip unchanged files in
// O(1) instead of re-serialising every row on each boot.
type RuleTemplate struct {
	ID             string     `json:"id" gorm:"primaryKey;type:varchar(128)"`
	Name           string     `json:"name" gorm:"type:varchar(255)"` // human-friendly display label
	Description    string     `json:"description,omitempty" gorm:"type:text"`
	Type           RuleType   `json:"type" gorm:"type:varchar(64)"`
	Mode           RuleMode   `json:"mode" gorm:"type:varchar(16)"`
	// ChainType narrows the template to one chain family. Empty value
	// is the off-chain bucket — rules that don't care which network
	// (sign_type_allowlist, rate_limit, time_window, ...).
	ChainType      ChainType  `json:"chain_type,omitempty" gorm:"type:varchar(32);index"`
	Variables      []byte     `json:"variables" gorm:"type:jsonb"`        // []TemplateVariable
	// VariableGroups is an optional UI-only directive for grouping
	// long forms into collapsible sections. Empty = one flat list.
	VariableGroups []byte     `json:"variable_groups,omitempty" gorm:"type:jsonb"` // []VariableGroup
	Config         []byte     `json:"config" gorm:"type:jsonb"`           // Template config with ${var} (contains rules array)
	BudgetMetering []byte     `json:"budget_metering,omitempty" gorm:"type:jsonb"` // *BudgetMetering (nullable)
	TestVariables  []byte     `json:"test_variables,omitempty" gorm:"type:jsonb"`  // map[string]string for template validation
	Source         RuleSource `json:"source" gorm:"type:varchar(32);index"`
	// SourcePath records where the row came from — a relative file
	// path for file sources, a URL for future github/http sources.
	// Empty for source=api (created via POST).
	SourcePath     string     `json:"source_path,omitempty" gorm:"type:varchar(512)"`
	// SourceRef pins a remote ref (commit SHA, tag, branch). File
	// sources leave this empty; remote sources should always populate
	// it so cached rows can be invalidated when the ref moves.
	SourceRef      string     `json:"source_ref,omitempty" gorm:"type:varchar(128)"`
	// ContentHash is SHA256 hex of the source YAML. Registry.Sync
	// compares this against the file's current hash before doing any
	// JSON marshalling, so unchanged templates touch one column read
	// per startup.
	ContentHash    string     `json:"content_hash,omitempty" gorm:"type:varchar(64);index"`
	Enabled        bool       `json:"enabled" gorm:"index"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// TableName specifies the table name for GORM
func (RuleTemplate) TableName() string {
	return "rule_templates"
}

// OperatorOverride lets a preset declare which template variables the
// operator can — or must — override at apply time. Replaces the older
// `override_hints: [string]` shape: keeping the same intent but
// promoted to a struct so we can carry per-variable required-ness and
// (later) per-override labels or constraints.
type OperatorOverride struct {
	Name     string `json:"name" yaml:"name"`
	Required bool   `json:"required" yaml:"required"`
}

// RulePreset is a saved bundle of (template_ids, variable defaults,
// budget, schedule, operator overrides) that an operator can apply
// with one POST. Until v0.3 presets lived only as YAML files on disk;
// the Registry now upserts them into this table so:
//
//   1. remote sources (github, http) have a stable cache location, and
//   2. the API can serve list/detail without rescanning the filesystem.
//
// Identity + provenance fields mirror RuleTemplate so the same Sync
// machinery applies to both kinds.
type RulePreset struct {
	ID                string     `json:"id" gorm:"primaryKey;type:varchar(128)"`
	Name              string     `json:"name" gorm:"type:varchar(255)"`
	Description       string     `json:"description,omitempty" gorm:"type:text"`
	ChainType         ChainType  `json:"chain_type,omitempty" gorm:"type:varchar(32);index"`
	ChainID           string     `json:"chain_id,omitempty" gorm:"type:varchar(32)"`
	// TemplateIDs is the list of template canonical IDs this preset
	// instantiates. JSON-encoded []string. Composite presets target
	// multiple templates with shared variables/budget/schedule.
	TemplateIDs       []byte     `json:"template_ids" gorm:"type:jsonb"`
	// Variables is the preset's own default values for the targeted
	// templates' variables. JSON-encoded map[string]any so the typed
	// shape (bool, []string, etc.) survives the round-trip.
	Variables         []byte     `json:"variables,omitempty" gorm:"type:jsonb"`
	// OperatorOverrides is JSON-encoded []OperatorOverride — which
	// variables the operator can/must change at apply time. Variables
	// not listed here are baked from the preset's Variables map.
	OperatorOverrides []byte     `json:"operator_overrides,omitempty" gorm:"type:jsonb"`
	// Budget / Schedule are JSON-encoded maps; values may contain
	// ${var} which is substituted at apply time against the resolved
	// variable map.
	Budget            []byte     `json:"budget,omitempty" gorm:"type:jsonb"`
	Schedule          []byte     `json:"schedule,omitempty" gorm:"type:jsonb"`
	// Matrix is an optional per-chain variable override table for
	// presets that use the rule-level Matrix feature. One rule
	// created from this preset serves all chains; the evaluator
	// resolves variables per request by looking up Matrix[chain_id].
	// Stored as JSONB: []map[string]any.
	Matrix            []byte     `json:"matrix,omitempty" gorm:"type:jsonb"`
	Enabled           bool       `json:"enabled" gorm:"index"`
	Source            RuleSource `json:"source" gorm:"type:varchar(32);index"`
	SourcePath        string     `json:"source_path,omitempty" gorm:"type:varchar(512)"`
	SourceRef         string     `json:"source_ref,omitempty" gorm:"type:varchar(128)"`
	ContentHash       string     `json:"content_hash,omitempty" gorm:"type:varchar(64);index"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// TableName specifies the table name for GORM
func (RulePreset) TableName() string {
	return "rule_presets"
}

// VariableType is the canonical type tag for a template variable. The
// substituter, validator, and UI widgets all dispatch on this string;
// adding a new kind means extending the enum + each of those layers.
//
// Semantics by type:
//
//   address       string — chain-specific format (EVM 0x+40hex, Solana
//                          base58, etc.); the surrounding template's
//                          chain_type field decides validation
//   address_list  []string
//   bigint        string — decimal big integer (precision-safe); sentinel
//                          "-1" allowed where the rule supports it.
//                          Replaces the EVM-flavored "uint256" name —
//                          same on-the-wire shape, chain-neutral name.
//   bigint_list   []string
//   string        string
//   bool          bool
//   bytes         string — 0x + even-length hex
//   bytes4        string — 0x + 8 hex (EVM function selector; kept as a
//                          named alias so calldata-param rules stay
//                          legible. Same wire format as bytes.)
//   duration      string — Go time.ParseDuration form ("30s", "24h")
//   enum          string — must appear in the variable's Options
//   json          any   — opaque; only syntactic validation
type VariableType string

const (
	VarTypeAddress     VariableType = "address"
	VarTypeAddressList VariableType = "address_list"
	VarTypeBigInt      VariableType = "bigint"
	VarTypeBigIntList  VariableType = "bigint_list"
	VarTypeString      VariableType = "string"
	VarTypeBool        VariableType = "bool"
	VarTypeBytes       VariableType = "bytes"
	VarTypeBytes4      VariableType = "bytes4"
	VarTypeDuration    VariableType = "duration"
	VarTypeEnum        VariableType = "enum"
	VarTypeJSON        VariableType = "json"
)

// IsValidVariableType reports whether s is one of the canonical
// variable types. Used by the registry's sync-time validator.
func IsValidVariableType(s string) bool {
	switch VariableType(s) {
	case VarTypeAddress, VarTypeAddressList,
		VarTypeBigInt, VarTypeBigIntList,
		VarTypeString, VarTypeBool,
		VarTypeBytes, VarTypeBytes4,
		VarTypeDuration, VarTypeEnum, VarTypeJSON:
		return true
	}
	return false
}

// TemplateVariable defines a variable on a rule template. The "core"
// fields (Name, Type, Required, Default) are load-bearing — they drive
// substitution and validation. The "UI" fields (Label, Placeholder,
// Hint, Sensitive) are operator ergonomics: the form renders better
// with them, but the substituter doesn't read them.
type TemplateVariable struct {
	// Name is the programmatic key used in ${var} substitution and in
	// apply requests. Stable; treat as code, not UX.
	Name string `json:"name" yaml:"name"`

	// Type is the canonical kind. See VariableType for the enum and
	// the wire shape each kind expects.
	Type VariableType `json:"type" yaml:"type"`

	// Label is the human-friendly title the UI shows above the input.
	// Falls back to Name when empty.
	Label string `json:"label,omitempty" yaml:"label,omitempty"`

	// Description is one or two sentences of context the operator
	// reads while filling the form. Render below the input.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Required gates apply: when true and no value is supplied (and
	// no Default), the daemon rejects the request.
	Required bool `json:"required" yaml:"required"`

	// Default is the value used when the operator omits the variable
	// at apply time. Type follows the Type field — string for address,
	// []string for address_list, bool for bool, etc. — so YAML carries
	// the natural shape without runtime parsing tricks.
	Default any `json:"default,omitempty" yaml:"default,omitempty"`

	// Placeholder is what the input box shows in ghost text before
	// the operator types. Useful for examples ("0xA0b8...").
	Placeholder string `json:"placeholder,omitempty" yaml:"placeholder,omitempty"`

	// Hint is a short tip rendered as muted text next to the input —
	// e.g. "Use -1 for unlimited". For longer guidance use Description.
	Hint string `json:"hint,omitempty" yaml:"hint,omitempty"`

	// Options enumerates the legal values for Type=enum. Validator
	// requires the operator-supplied value to appear in this list.
	Options []string `json:"options,omitempty" yaml:"options,omitempty"`

	// Sensitive marks a variable that carries credentials. The UI
	// masks it (password input), the audit log redacts the value.
	// Daemon enforcement is best-effort — operators should still keep
	// secrets out of YAML.
	Sensitive bool `json:"sensitive,omitempty" yaml:"sensitive,omitempty"`

	// Pattern is an optional regex constraint, applied after the
	// type-specific format check. Empty = no extra constraint.
	Pattern string `json:"pattern,omitempty" yaml:"pattern,omitempty"`

	// Min / Max bound numeric values (uint256, duration). For
	// uint256 they're decimal big-int strings; for duration they're
	// Go duration forms ("1h"). nil = unbounded.
	Min *string `json:"min,omitempty" yaml:"min,omitempty"`
	Max *string `json:"max,omitempty" yaml:"max,omitempty"`
}

// VariableGroup is an optional grouping hint for long forms. The UI
// renders one section per group, in declared order, with any variables
// not named in any group falling into an "Other" trailing section.
type VariableGroup struct {
	Title       string   `json:"title" yaml:"title"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Variables   []string `json:"variables" yaml:"variables"`
}

// BudgetMetering defines how to extract "spend amount" from each request for budget enforcement.
//
// Design: budget limits and usage are stored per rule instance (rule_id + unit). Metering lives
// on the template so extraction semantics stay fixed—operators tune limits per instance without
// accidentally changing how amounts are measured.
type BudgetMetering struct {
	Method     string `json:"method" yaml:"method"`                          // "none", "count_only", "calldata_param", "typed_data_field", "tx_value", "js"
	Unit       string `json:"unit" yaml:"unit"`                              // custom unit: "usdt", "auth", "eth"
	ParamIndex int    `json:"param_index,omitempty" yaml:"param_index,omitempty"` // for calldata_param
	ParamType  string `json:"param_type,omitempty" yaml:"param_type,omitempty"`   // for calldata_param: "uint256", etc.
	FieldPath  string `json:"field_path,omitempty" yaml:"field_path,omitempty"`   // for typed_data_field: "message.amount"
	Decimals   int    `json:"decimals,omitempty" yaml:"decimals,omitempty"`

	// Dynamic budget: when true, validateBudget may return {amount, unit} and the unit
	// is resolved at evaluation time rather than being fixed at rule creation.
	Dynamic      bool                `json:"dynamic,omitempty" yaml:"dynamic,omitempty"`
	UnitDecimal  bool                `json:"unit_decimal,omitempty" yaml:"unit_decimal,omitempty"`
	KnownUnits   map[string]UnitConf `json:"known_units,omitempty" yaml:"known_units,omitempty"`
	UnknownDefault *UnitConf         `json:"unknown_default,omitempty" yaml:"unknown_default,omitempty"`

	// SECURITY: MaxDynamicUnits caps the number of distinct dynamic budget units per rule.
	// Without this, an attacker could target N different tokens to get N * max_total effective budget.
	// Default: 100. Set to 0 to disable (not recommended).
	MaxDynamicUnits int `json:"max_dynamic_units,omitempty" yaml:"max_dynamic_units,omitempty"`
}

// UnitConf defines budget limits for a known or unknown dynamic budget unit.
type UnitConf struct {
	MaxTotal   string `json:"max_total" yaml:"max_total"`
	MaxPerTx   string `json:"max_per_tx,omitempty" yaml:"max_per_tx,omitempty"`
	MaxTxCount int    `json:"max_tx_count,omitempty" yaml:"max_tx_count,omitempty"`
	Decimals   int    `json:"decimals,omitempty" yaml:"decimals,omitempty"` // explicit decimals; 0 means auto-query
	AlertPct   int    `json:"alert_pct,omitempty" yaml:"alert_pct,omitempty"`
}
