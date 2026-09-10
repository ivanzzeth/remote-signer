package types

import (
	"time"

	"github.com/lib/pq"
)

// RuleID is a unique identifier for rules
type RuleID string

// RuleType represents the type of rule
type RuleType string

const (
	// Chain-agnostic rule types
	RuleTypeSignerRestriction   RuleType = "signer_restriction"
	RuleTypeChainRestriction    RuleType = "chain_restriction"
	RuleTypeSignTypeRestriction RuleType = "sign_type_restriction"
	RuleTypeMessagePattern      RuleType = "message_pattern" // regex pattern matching for personal sign messages

	// EVM-specific rule types (prefixed)
	// Mode (whitelist/blocklist) determines behavior, not the type name
	RuleTypeEVMAddressList        RuleType = "evm_address_list"        // address list (whitelist mode = allow, blocklist mode = block)
	RuleTypeEVMContractMethod     RuleType = "evm_contract_method"     // contract method restriction
	RuleTypeEVMValueLimit         RuleType = "evm_value_limit"         // value limit check
	RuleTypeEVMSolidityExpression RuleType = "evm_solidity_expression" // Solidity expression rules (Foundry-based)
	RuleTypeEVMJS                 RuleType = "evm_js"                  // JS rules (in-process Sobek); validate(input) → { valid, reason?, payload? }
	RuleTypeEVMDynamicBlocklist   RuleType = "evm_dynamic_blocklist"   // Dynamic blocklist: runtime-synced from external URLs (OFAC, scam DBs)
	RuleTypeEVMInternalTransfer   RuleType = "evm_internal_transfer"   // Internal transfer: same-owner signer transfers (whitelist-only)

	// ⛔ A new rule type is not finished at this line. Add it to ruleTypes
	// below — everything else in the tree derives from that table, and the
	// completeness test refuses a constant that is not in it.
)

// RuleTypeDescriptor is what the rest of the tree needs to know about a rule
// type without naming the type.
//
// ⚠️ Callers used to answer these questions by comparing against a constant —
// `if rule.Type == RuleTypeEVMJS && len(req.TestCases) > 0`, and a whole file
// named solidity_guard.go in the delivery layer. Nine files did that, and the
// list of rule types was written out five times over: these constants, the
// ValidRuleTypes map, ruleconfig's config-validation switch, the CLI validate
// branches and the evaluator wiring.
//
// ⛔ That is not a style problem. evm_internal_transfer was registered as an
// evaluator in four places and left out of ValidRuleTypes, so a fully wired
// engine rejected every attempt to create a rule for it — via the API, via a
// template, and via config — and no shipped rule used it, so nobody hit it.
// A map lookup and a switch with a default both accept an unlisted type in
// silence; only a single table plus a completeness test does not.
type RuleTypeDescriptor struct {
	Type RuleType

	// ChainAgnostic marks a type that does not belong to one chain family.
	ChainAgnostic bool

	// TakesTestCases marks an engine whose rules carry test_cases that the
	// engine itself can run. Callers ask this instead of naming evm_js.
	TakesTestCases bool

	// RequiresToolchain names the external binary the engine shells out to,
	// empty for engines that run in-process. Callers ask this instead of
	// naming evm_solidity_expression.
	//
	// ⚠️ The executable, not the suite: this string reaches the operator in an
	// error message, and "forge" is what they install and can check with
	// `which`. Naming the suite ("foundry") sends them to the config key
	// instead of to the thing that is missing.
	//
	// ⚠️ A rule of such a type cannot be evaluated on a deployment that has
	// not configured that toolchain, which is what the delivery layer needs
	// to warn about before a template is applied.
	RequiresToolchain string

	// ExecutesArbitraryCode marks an engine that runs operator-supplied code
	// rather than matching a declared shape. Whoever can write such a rule can
	// express any predicate the sandbox allows.
	ExecutesArbitraryCode bool

	// GovernsSignerAccess marks a type that decides which signers may be used
	// at all, rather than what a signer may do. Writing one is a change to who
	// holds authority, not to policy under that authority.
	GovernsSignerAccess bool
}

// ruleTypes is the one list of rule types. Everything else derives from it.
var ruleTypes = []RuleTypeDescriptor{
	{Type: RuleTypeSignerRestriction, ChainAgnostic: true, GovernsSignerAccess: true},
	{Type: RuleTypeChainRestriction, ChainAgnostic: true},
	{Type: RuleTypeSignTypeRestriction, ChainAgnostic: true},
	{Type: RuleTypeMessagePattern, ChainAgnostic: true},
	{Type: RuleTypeEVMAddressList},
	{Type: RuleTypeEVMContractMethod},
	{Type: RuleTypeEVMValueLimit},
	{Type: RuleTypeEVMSolidityExpression, RequiresToolchain: "forge", ExecutesArbitraryCode: true},
	{Type: RuleTypeEVMJS, TakesTestCases: true, ExecutesArbitraryCode: true},
	{Type: RuleTypeEVMDynamicBlocklist},
	{Type: RuleTypeEVMInternalTransfer},
}

// RuleTypes returns every declared rule type, in declaration order.
func RuleTypes() []RuleTypeDescriptor {
	out := make([]RuleTypeDescriptor, len(ruleTypes))
	copy(out, ruleTypes)
	return out
}

// LookupRuleType returns the descriptor for t.
//
// ⚠️ ok=false means the type is not declared at all — not that it is disabled.
// Callers gating on "is this a real rule type" should use this rather than
// keeping their own set.
func LookupRuleType(t RuleType) (RuleTypeDescriptor, bool) {
	for _, d := range ruleTypes {
		if d.Type == t {
			return d, true
		}
	}
	return RuleTypeDescriptor{}, false
}

// RuleSource represents where the rule came from
type RuleSource string

const (
	RuleSourceConfig        RuleSource = "config"
	RuleSourceAPI           RuleSource = "api"
	RuleSourceAutoGenerated RuleSource = "auto_generated"
	RuleSourceInstance      RuleSource = "instance" // created from template
	// RuleSourceFile is the kind Registry+FileSource use for templates
	// and presets discovered by walking rules/templates and rules/presets
	// on disk. Kept distinct from RuleSourceConfig so the legacy
	// TemplateInitializer (which prunes Source=config rows missing from
	// cfg.Templates) doesn't fight Registry over the same row.
	RuleSourceFile RuleSource = "file"
)

// RuleMode represents how the rule is evaluated
type RuleMode string

const (
	// RuleModeWhitelist - ANY match = allow (permissive)
	// Used for: address whitelist, contract method whitelist
	RuleModeWhitelist RuleMode = "whitelist"

	// RuleModeBlocklist - ANY violation = block immediately (restrictive)
	// Used for: value limits, rate limits, global restrictions
	// Blocklist rules are evaluated BEFORE whitelist rules
	// If ANY blocklist rule is violated, request is rejected (no manual approval)
	RuleModeBlocklist RuleMode = "blocklist"
)

// RuleStatus represents the lifecycle status of a rule.
type RuleStatus string

const (
	RuleStatusActive          RuleStatus = "active"
	RuleStatusPendingApproval RuleStatus = "pending_approval"
	RuleStatusRejected        RuleStatus = "rejected"
	RuleStatusRevoked         RuleStatus = "revoked"
	RuleStatusSuperseded      RuleStatus = "superseded"
)

// Rule represents a signing authorization rule
type Rule struct {
	ID          RuleID     `json:"id" gorm:"primaryKey;type:varchar(64)"`
	Name        string     `json:"name" gorm:"type:varchar(255)"`
	Description string     `json:"description,omitempty" gorm:"type:text"`
	Type        RuleType   `json:"type" gorm:"index;type:varchar(64)"`
	Mode        RuleMode   `json:"mode" gorm:"index;type:varchar(16);default:'whitelist'"` // whitelist or blocklist
	Source      RuleSource `json:"source" gorm:"type:varchar(32)"`

	// Scope
	ChainType     *ChainType `json:"chain_type,omitempty" gorm:"index;type:varchar(32)"` // nil = all chains
	ChainID       *string    `json:"chain_id,omitempty" gorm:"type:varchar(32)"`
	SignerAddress *string    `json:"signer_address,omitempty" gorm:"index;type:varchar(128)"`

	// Ownership & scoping
	// Owner is the API key ID that created this rule. "config" for rules from config file / preset CLI.
	Owner string `json:"owner" gorm:"type:varchar(64);not null;default:'config';index"`
	// AppliedTo controls which API keys this rule affects at runtime.
	// ["*"] = all keys (admin only), ["self"] = owner only (default for non-admin),
	// ["key-1", "key-2"] = specific keys (admin only).
	AppliedTo pq.StringArray `json:"applied_to" gorm:"type:text[];not null"`
	// Status: "active", "pending_approval", "rejected", "revoked"
	Status RuleStatus `json:"status" gorm:"type:varchar(32);not null;default:'active';index"`
	// ApprovedBy: admin key ID that approved a pending rule.
	ApprovedBy *string `json:"approved_by,omitempty" gorm:"type:varchar(64)"`
	// Immutable: when true, rule cannot be modified or deleted via API.
	Immutable bool `json:"immutable" gorm:"default:false"`

	// ProposalFor is set when this rule is a proposed update to another rule.
	// It points to the target rule ID. nil means this is a regular rule, not a proposal.
	// When the proposal is approved, the changes are applied to the target rule and
	// this proposal row is marked rejected (preserving the audit trail).
	ProposalFor *RuleID `json:"proposal_for,omitempty" gorm:"index;type:varchar(64)"`

	// RejectionReason stores why an admin rejected a pending_approval rule or proposal.
	RejectionReason *string `json:"rejection_reason,omitempty" gorm:"type:text"`

	// Chain-specific config stored as JSON
	Config []byte `json:"config" gorm:"type:jsonb"`

	// Template instance fields (nullable, backward compatible)
	TemplateID *string `json:"template_id,omitempty" gorm:"type:varchar(128)"`
	Variables  []byte  `json:"variables,omitempty" gorm:"type:jsonb"` // map[string]string — bound variable values

	// Matrix is an optional per-chain variable override table.
	// When non-nil, the evaluator resolves variables for a request by first
	// loading Variables (defaults), then looking up Matrix[chain_id] and
	// merging the per-chain overrides on top. ChainID on the rule is nil
	// when Matrix is used — the rule matches ALL chains, but variables are
	// resolved per-request based on the sign-request's chain_id.
	// Stored as JSONB: []map[string]interface{}.
	Matrix []byte `json:"matrix,omitempty" gorm:"type:jsonb"`

	// Schedule fields — for periodic budget renewal
	// When BudgetPeriod is set, the instance automatically renews its budget
	// at each period boundary. ExpiresAt still controls the overall lifetime.
	BudgetPeriod      *time.Duration `json:"budget_period,omitempty" gorm:"type:bigint"` // e.g. 24h, 7*24h
	BudgetPeriodStart *time.Time     `json:"budget_period_start,omitempty"`              // when the first period begins (SQLite: datetime, PostgreSQL: timestamptz)

	Enabled   bool       `json:"enabled" gorm:"index"`
	Priority  int        `json:"priority" gorm:"index;default:100"` // lower = higher priority, 1 is highest
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	MatchCount    uint64     `json:"match_count"`
	LastMatchedAt *time.Time `json:"last_matched_at,omitempty"`
}

// CoalesceRulePriority turns an optional YAML/JSON `priority` into the value
// stored on Rule.Priority.
//
// nil (author wrote no priority) → 100, matching the GORM column default, so a
// rule that says nothing keeps sorting where it always did.
// < 1 → 1, because 1 is the documented maximum and a 0 or negative would sort
// ahead of it and silently outrank every rule an author *did* prioritise.
//
// ⚠️ Callers: this is the ONLY implementation. There were two — one in
// core/service (template instantiation via API / preset apply) and one in
// cli/server (agent preset seeding) — and a third path, config.yaml instance
// expansion, had none at all: `config.RuleConfig` carried no Priority field, so
// `priority: 10000` written in a template was silently dropped by
// json.Unmarshal and the rule landed at the default 100. The same template
// therefore produced differently-ordered rules depending on which path created
// it, and whitelist order decides which spending authorization applies.
// Found 2026-09-09 by an e2e budget test: a broad `evm_value_limit` fixture rule
// matched an ERC20 transfer first, so the budgeted rule was never reached and
// its budget stayed at 0.
func CoalesceRulePriority(p *int) int {
	if p == nil {
		return 100
	}
	if *p < 1 {
		return 1
	}
	return *p
}

// TableName specifies the table name for GORM
func (Rule) TableName() string {
	return "rules"
}

// RuleEvaluationResult represents the result of rule evaluation
type RuleEvaluationResult struct {
	RuleID      RuleID    `json:"rule_id"`
	Matched     bool      `json:"matched"`
	Reason      string    `json:"reason,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}
