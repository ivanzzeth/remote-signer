package rule

import (
	"context"
	"regexp"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const (
	// defaultMaxDynamicUnits is the default cap on distinct dynamic budget units per rule.
	// SECURITY: Without this cap, an attacker could target N tokens to get N * max_total effective budget.
	defaultMaxDynamicUnits = 100

	// maxDecimalDigits is the maximum token decimals allowed.
	// SECURITY: PostgreSQL NUMERIC precision is ~131072 digits. 77 decimals can represent
	// up to 10^77, which is far beyond any realistic token. Values above this risk overflow.
	maxDecimalDigits = 77

	// maxUnitLength caps the unit string length to prevent storage abuse.
	maxUnitLength = 256
)

// validDynamicUnitRe matches safe dynamic unit strings.
// Allowed patterns:
//   - Hex address: 0x followed by 40 hex chars, optionally with :suffix (e.g. 0xAbC123...:approve)
//   - Named units: alphanumeric with underscores (e.g. native, tx_count, sign_count)
var validDynamicUnitRe = regexp.MustCompile(`^(?:0x[0-9a-fA-F]{1,40}(?::[a-z_0-9]+)?|[a-zA-Z][a-zA-Z0-9_]*)$`)

// BudgetAlertNotifier sends budget alert notifications.
// Implementations should be non-blocking (async) to avoid delaying sign requests.
type BudgetAlertNotifier interface {
	// SendBudgetAlert sends an alert notification when budget usage reaches the threshold.
	SendBudgetAlert(ctx context.Context, ruleID types.RuleID, unit string, spent string, maxTotal string, pct int64, alertPct int) error
}

// BudgetJSEvaluator evaluates the spend amount for evm_js rules when budget_metering.method is "js".
// The script's validateBudget(input) is called and must return a bigint, decimal string,
// or {amount, unit} object for dynamic budget support.
type BudgetJSEvaluator interface {
	EvaluateBudget(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (*types.BudgetResult, error)
}

// DecimalsQuerier queries ERC20 token decimals via RPC.
// Implementations should use caching (e.g. TokenMetadataCache) to avoid redundant RPC calls.
type DecimalsQuerier interface {
	// QueryDecimals returns the decimals for the given token address on the given chain.
	// Returns an error if the RPC call fails or the contract does not implement decimals().
	QueryDecimals(ctx context.Context, chainID, address string) (int, error)
}

// isEthAddressRe matches a 0x-prefixed hex string of exactly 40 hex characters (Ethereum address).
var isEthAddressRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
