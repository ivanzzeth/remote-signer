package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// BudgetAlertNotifier sends budget alert notifications.
// Implementations should be non-blocking (async) to avoid delaying sign requests.
type BudgetAlertNotifier interface {
	// SendBudgetAlert sends an alert notification when budget usage reaches the threshold.
	SendBudgetAlert(ctx context.Context, ruleID types.RuleID, unit string, spent string, maxTotal string, pct int64, alertPct int) error
}

// BudgetChecker checks and deducts budget for rule instances
type BudgetChecker struct {
	budgetRepo   storage.BudgetRepository
	templateRepo storage.TemplateRepository
	notifier     BudgetAlertNotifier
	logger       *slog.Logger
}

// NewBudgetChecker creates a new budget checker
func NewBudgetChecker(
	budgetRepo storage.BudgetRepository,
	templateRepo storage.TemplateRepository,
	logger *slog.Logger,
) *BudgetChecker {
	return &BudgetChecker{
		budgetRepo:   budgetRepo,
		templateRepo: templateRepo,
		logger:       logger,
	}
}

// SetNotifier sets the budget alert notifier.
// This is a setter instead of a constructor param because the NotifyService may
// be created after the BudgetChecker in the application initialization order.
func (bc *BudgetChecker) SetNotifier(n BudgetAlertNotifier) {
	bc.notifier = n
}

// CheckAndDeductBudget checks if the rule has budget and deducts the spending amount.
// Returns:
//   - (true, nil) if budget is available or no budget constraint
//   - (false, nil) if budget is exceeded
//   - (false, err) if an error occurred
func (bc *BudgetChecker) CheckAndDeductBudget(
	ctx context.Context,
	rule *types.Rule,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (bool, error) {
	if bc.budgetRepo == nil || rule.TemplateID == nil {
		// No budget system or not an instance rule — pass through
		return true, nil
	}

	// Load template to get BudgetMetering
	tmpl, err := bc.templateRepo.Get(ctx, *rule.TemplateID)
	if err != nil {
		if types.IsNotFound(err) {
			// SECURITY: template deleted but instance still active — fail-closed.
			// The budget constraint cannot be verified without the template.
			return false, fmt.Errorf("template %s deleted but instance rule %s still active", *rule.TemplateID, rule.ID)
		}
		return false, fmt.Errorf("failed to load template: %w", err)
	}

	// Parse budget metering
	var metering types.BudgetMetering
	if len(tmpl.BudgetMetering) == 0 {
		// No metering defined — no budget constraint
		return true, nil
	}
	if err := json.Unmarshal(tmpl.BudgetMetering, &metering); err != nil {
		return false, fmt.Errorf("failed to parse budget metering: %w", err)
	}

	if metering.Method == "" || metering.Method == "none" {
		return true, nil
	}

	unit := metering.Unit
	if unit == "" {
		unit = "count"
	}

	// Get budget for this rule+unit
	budget, err := bc.budgetRepo.GetByRuleID(ctx, rule.ID, unit)
	if err != nil {
		if types.IsNotFound(err) {
			// SECURITY: no budget record for a rule with metering — fail-closed.
			// Budget record should be created at rule initialization. Missing record
			// means incomplete setup; allowing would bypass budget constraints.
			return false, fmt.Errorf("no budget record for rule %s (unit=%s) with metering method %q", rule.ID, unit, metering.Method)
		}
		return false, fmt.Errorf("failed to get budget: %w", err)
	}

	// Check periodic renewal
	// SECURITY: fail-closed on renewal error — stale budget data could allow
	// spending beyond the intended period limit.
	if err := bc.checkPeriodicRenewal(ctx, rule, budget, unit); err != nil {
		return false, fmt.Errorf("failed to check periodic renewal for rule %s: %w", rule.ID, err)
	}

	// Extract spending amount
	amount, err := ExtractAmount(metering, req, parsed)
	if err != nil {
		return false, fmt.Errorf("failed to extract amount: %w", err)
	}

	// Check per-tx limit
	// SECURITY: fail-closed on parse error — unparseable limit could allow
	// arbitrarily large transactions.
	if budget.MaxPerTx != "" && budget.MaxPerTx != "0" {
		maxPerTx := new(big.Int)
		if _, ok := maxPerTx.SetString(budget.MaxPerTx, 10); !ok {
			return false, fmt.Errorf("invalid max_per_tx value %q for rule %s", budget.MaxPerTx, rule.ID)
		}
		if amount.Cmp(maxPerTx) > 0 {
			bc.logger.Warn("per-tx budget exceeded",
				"rule_id", rule.ID,
				"amount", amount.String(),
				"max_per_tx", budget.MaxPerTx,
			)
			return false, nil
		}
	}

	// Atomic spend (checks total budget and tx count atomically)
	if err := bc.budgetRepo.AtomicSpend(ctx, rule.ID, unit, amount.String()); err != nil {
		if err == storage.ErrBudgetExceeded {
			bc.logger.Warn("total budget exceeded",
				"rule_id", rule.ID,
				"unit", unit,
				"amount", amount.String(),
			)
			return false, nil
		}
		return false, fmt.Errorf("failed to deduct budget: %w", err)
	}

	// Log at Info so operators can verify budget usage and periodic renewal in production
	bc.logger.Info("budget deducted",
		"rule_id", rule.ID,
		"unit", unit,
		"amount", amount.String(),
		"max_total", budget.MaxTotal,
		"tx_count_after", budget.TxCount+1,
	)

	// #nosec G118 -- intentional: async alert check must outlive request context
	go bc.checkAlertThreshold(rule.ID, unit, budget)

	return true, nil
}

// checkPeriodicRenewal checks if the budget needs to be reset for a new period
func (bc *BudgetChecker) checkPeriodicRenewal(ctx context.Context, rule *types.Rule, budget *types.RuleBudget, unit string) error {
	if rule.BudgetPeriod == nil || rule.BudgetPeriodStart == nil {
		return nil // No periodic renewal
	}

	now := time.Now()
	period := *rule.BudgetPeriod
	start := *rule.BudgetPeriodStart

	if period <= 0 || now.Before(start) {
		return nil
	}

	// Calculate current period
	elapsed := now.Sub(start)
	periodIndex := int64(elapsed / period)
	currentPeriodStart := start.Add(time.Duration(periodIndex) * period)

	// If budget was updated before current period, it belongs to an old period — reset
	if budget.UpdatedAt.Before(currentPeriodStart) {
		bc.logger.Info("resetting budget for new period",
			"rule_id", rule.ID,
			"unit", unit,
			"period_index", periodIndex,
			"current_period_start", currentPeriodStart,
		)
		return bc.budgetRepo.ResetBudget(ctx, rule.ID, unit, currentPeriodStart)
	}

	return nil
}

// checkAlertThreshold checks if the budget usage has reached the alert threshold.
// When reached, sends a notification (if notifier is configured) and marks
// the alert as sent to prevent duplicate notifications within the same period.
func (bc *BudgetChecker) checkAlertThreshold(ruleID types.RuleID, unit string, budget *types.RuleBudget) {
	if budget.AlertSent || budget.AlertPct <= 0 || budget.MaxTotal == "" || budget.MaxTotal == "0" {
		return
	}

	spent := new(big.Int)
	maxTotal := new(big.Int)

	if _, ok := spent.SetString(budget.Spent, 10); !ok {
		return
	}
	if _, ok := maxTotal.SetString(budget.MaxTotal, 10); !ok {
		return
	}

	// Calculate percentage: (spent * 100) / maxTotal
	pct := new(big.Int).Mul(spent, big.NewInt(100))
	pct.Div(pct, maxTotal)

	if pct.Int64() >= int64(budget.AlertPct) {
		bc.logger.Warn("budget alert threshold reached",
			"rule_id", ruleID,
			"unit", unit,
			"spent", budget.Spent,
			"max_total", budget.MaxTotal,
			"pct", pct.Int64(),
			"alert_pct", budget.AlertPct,
		)

		// Send notification via notify system
		if bc.notifier != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := bc.notifier.SendBudgetAlert(ctx, ruleID, unit, budget.Spent, budget.MaxTotal, pct.Int64(), budget.AlertPct); err != nil {
				bc.logger.Error("failed to send budget alert notification",
					"rule_id", ruleID,
					"unit", unit,
					"error", err,
				)
				// Don't mark as sent if notification failed — retry next time
				return
			}
		}

		// Mark alert as sent to prevent duplicate notifications
		if bc.budgetRepo != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := bc.budgetRepo.MarkAlertSent(ctx, ruleID, unit); err != nil {
				bc.logger.Error("failed to mark budget alert as sent",
					"rule_id", ruleID,
					"unit", unit,
					"error", err,
				)
			}
		}
	}
}

// ExtractAmount extracts the spending amount from a request based on the metering method
func ExtractAmount(metering types.BudgetMetering, req *types.SignRequest, parsed *types.ParsedPayload) (*big.Int, error) {
	switch metering.Method {
	case "count_only":
		return big.NewInt(1), nil
	case "tx_value":
		return extractTxValue(parsed)
	case "calldata_param":
		return extractCalldataParam(metering, parsed)
	case "typed_data_field":
		return extractTypedDataField(metering, parsed)
	default:
		// SECURITY: Unknown metering method should return an error, not zero.
		// Returning zero would effectively bypass budget enforcement.
		return nil, fmt.Errorf("unknown metering method: %s", metering.Method)
	}
}

// extractTxValue extracts the transaction value from parsed payload.
// SECURITY: Returns an error when value is missing to prevent zero-cost budget bypass.
func extractTxValue(parsed *types.ParsedPayload) (*big.Int, error) {
	if parsed == nil || parsed.Value == nil {
		return nil, fmt.Errorf("tx_value metering requires a transaction value but parsed payload is nil or has no value")
	}
	n := new(big.Int)
	if _, ok := n.SetString(*parsed.Value, 10); !ok {
		// Try hex
		if _, ok := n.SetString(strings.TrimPrefix(*parsed.Value, "0x"), 16); !ok {
			return nil, fmt.Errorf("cannot parse value '%s' as number", *parsed.Value)
		}
	}
	return n, nil
}

// extractCalldataParam extracts a parameter from calldata using ABI decoding.
// Uses RawData from ParsedPayload which contains the raw transaction data.
// SECURITY: Returns an error when data is missing to prevent zero-cost budget bypass.
func extractCalldataParam(metering types.BudgetMetering, parsed *types.ParsedPayload) (*big.Int, error) {
	if parsed == nil || len(parsed.RawData) == 0 {
		return nil, fmt.Errorf("calldata_param metering requires raw transaction data but parsed payload is nil or has no data")
	}

	// Calldata format: 4-byte selector + 32-byte parameters
	data := parsed.RawData
	if len(data) < 4 {
		return nil, fmt.Errorf("calldata_param metering requires at least 4 bytes of calldata, got %d", len(data))
	}

	params := data[4:]
	paramOffset := metering.ParamIndex * 32

	if paramOffset+32 > len(params) {
		return nil, fmt.Errorf("calldata too short for param_index %d (need %d bytes, have %d)",
			metering.ParamIndex, paramOffset+32, len(params))
	}

	// Extract 32-byte parameter
	paramBytes := params[paramOffset : paramOffset+32]
	amount := new(big.Int).SetBytes(paramBytes)

	return amount, nil
}

// extractTypedDataField extracts a field from EIP-712 typed data message.
// Uses RawData which may contain the typed data JSON, then navigates by field path.
// SECURITY: Returns an error when data is missing to prevent zero-cost budget bypass.
func extractTypedDataField(metering types.BudgetMetering, parsed *types.ParsedPayload) (*big.Int, error) {
	if parsed == nil || len(parsed.RawData) == 0 {
		return nil, fmt.Errorf("typed_data_field metering requires raw data but parsed payload is nil or has no data")
	}

	fieldPath := metering.FieldPath
	if fieldPath == "" {
		return nil, fmt.Errorf("typed_data_field metering requires field_path but it is empty")
	}

	// Try to parse RawData as JSON (typed data payload)
	var typedData map[string]interface{}
	if err := json.Unmarshal(parsed.RawData, &typedData); err != nil {
		return nil, fmt.Errorf("failed to parse raw data as JSON for typed_data_field: %w", err)
	}

	// Navigate the field path (e.g., "message.amount" or just "amount")
	parts := strings.Split(fieldPath, ".")
	var current interface{} = typedData

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			next, ok := v[part]
			if !ok {
				return nil, fmt.Errorf("field '%s' not found in typed data path '%s'", part, fieldPath)
			}
			current = next
		default:
			return nil, fmt.Errorf("cannot navigate into non-map type at '%s' in path '%s'", part, fieldPath)
		}
	}

	// Convert to big.Int
	return valueToBigInt(current)
}

// valueToBigInt converts various types to *big.Int
func valueToBigInt(v interface{}) (*big.Int, error) {
	switch val := v.(type) {
	case string:
		n := new(big.Int)
		if _, ok := n.SetString(val, 10); !ok {
			// Try hex
			if _, ok := n.SetString(strings.TrimPrefix(val, "0x"), 16); !ok {
				return nil, fmt.Errorf("cannot parse '%s' as number", val)
			}
		}
		return n, nil
	case float64:
		// SECURITY: Use big.Float to avoid precision loss for large values.
		// big.NewInt(int64(val)) loses precision for values > 2^53.
		bf := new(big.Float).SetFloat64(val)
		n, accuracy := bf.Int(nil)
		if accuracy != big.Exact {
			// Not an exact integer — could indicate precision issues
			return nil, fmt.Errorf("float64 value %v is not an exact integer (precision loss risk)", val)
		}
		return n, nil
	case int64:
		return big.NewInt(val), nil
	case json.Number:
		n := new(big.Int)
		if _, ok := n.SetString(val.String(), 10); !ok {
			return nil, fmt.Errorf("cannot parse json.Number '%s' as big.Int", val.String())
		}
		return n, nil
	default:
		return nil, fmt.Errorf("unsupported type %T for budget amount", v)
	}
}
