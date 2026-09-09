package ports

import (
	"fmt"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Sentinel errors callers match on with errors.Is.
//
// They live with the interfaces that return them rather than with the store
// that produces them: a caller deciding what to do about an exceeded budget is
// reasoning about the domain, not about the database. Keeping them in
// internal/storage forced the use-case layer to import the adapter just to name
// a condition it defines.
var (
	// ErrBudgetExceeded is returned when a spend would take a budget past its
	// cap. The signing path turns this into a refusal, not an error page.
	ErrBudgetExceeded = fmt.Errorf("budget exceeded")

	// ErrStateConflict is returned when a request's status changed underneath a
	// transition — someone else approved or rejected it first. The caller
	// re-reads rather than retrying blindly.
	ErrStateConflict = fmt.Errorf("state conflict: status was modified by another request")
)

// SyntheticBudgetRuleID returns the rule_id used for SimulationBudgetRule
// budgets: sim:<signer>.
//
// It is a naming rule, not a storage concern — the same string has to be
// produced by whatever is tracking the budget, in memory or in a database, or
// the two disagree about which row they mean.
func SyntheticBudgetRuleID(signerAddress string) types.RuleID {
	return types.RuleID("sim:" + strings.ToLower(signerAddress))
}
