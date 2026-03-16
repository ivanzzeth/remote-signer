package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
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

// BudgetChecker checks and deducts budget for rule instances
type BudgetChecker struct {
	budgetRepo   storage.BudgetRepository
	templateRepo storage.TemplateRepository
	notifier     BudgetAlertNotifier
	jsEvaluator  BudgetJSEvaluator // optional: for method "js" budget metering
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

// SetJSEvaluator sets the JS evaluator for budget_metering method "js".
// Required when any template uses method "js"; otherwise CheckAndDeductBudget fails closed for those rules.
func (bc *BudgetChecker) SetJSEvaluator(eval BudgetJSEvaluator) {
	bc.jsEvaluator = eval
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

	// For dynamic budget with JS method, the unit is determined at evaluation time,
	// so we defer budget lookup until after JS evaluation.
	if metering.Dynamic && metering.Method == "js" {
		return bc.checkDynamicBudget(ctx, rule, req, parsed, metering)
	}

	unit := metering.Unit
	if unit == "" {
		unit = "count"
	}
	// Substitute rule instance variables so unit matches the budget record created at sync (e.g. "${chain_id}:${token_address}" -> "1:0xA0b8...").
	unit = substituteUnitVariables(unit, rule.Variables)
	// Normalize so lookup matches stored unit regardless of address casing (0xA0b8 vs 0xa0b8).
	unit = NormalizeBudgetUnit(unit)

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

	// Extract spending amount (method "js" uses JS evaluator; others use ExtractAmount)
	var amount *big.Int
	if metering.Method == "js" {
		if bc.jsEvaluator == nil {
			return false, fmt.Errorf("budget metering method %q requires SetJSEvaluator to be set", metering.Method)
		}
		budgetResult, evalErr := bc.jsEvaluator.EvaluateBudget(ctx, rule, req, parsed)
		if evalErr != nil {
			return false, fmt.Errorf("js budget evaluation: %w", evalErr)
		}
		amount = budgetResult.Amount
	} else {
		amount, err = ExtractAmount(metering, req, parsed)
		if err != nil {
			return false, fmt.Errorf("failed to extract amount: %w", err)
		}
	}

	// Check per-tx limit. Only -1 means no cap; 0 means cap of 0.
	// SECURITY: fail-closed on parse error — unparseable limit could allow
	// arbitrarily large transactions.
	if budget.MaxPerTx != "" && budget.MaxPerTx != "-1" {
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

// checkDynamicBudget handles the dynamic budget path where the unit is determined by JS evaluation.
// Called when metering.Dynamic is true and method is "js".
//
// SECURITY (HIGH-1 known limitation): A single multicall TX that batches N transfers
// only costs 1 tx_count. This is a v1 trade-off; the per-token amount budget still applies
// to each transfer's decoded amount if the JS validateBudget correctly decodes the inner calls.
// For multicall-unaware scripts, the tx_count fallback undercounts. Document in operator guide.
func (bc *BudgetChecker) checkDynamicBudget(
	ctx context.Context,
	rule *types.Rule,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
	metering types.BudgetMetering,
) (bool, error) {
	if bc.jsEvaluator == nil {
		return false, fmt.Errorf("budget metering method %q requires SetJSEvaluator to be set", metering.Method)
	}

	budgetResult, evalErr := bc.jsEvaluator.EvaluateBudget(ctx, rule, req, parsed)
	if evalErr != nil {
		return false, fmt.Errorf("js budget evaluation: %w", evalErr)
	}

	amount := budgetResult.Amount
	rawUnit := budgetResult.Unit
	if rawUnit == "" {
		return false, fmt.Errorf("dynamic budget JS must return {amount, unit} but unit was empty")
	}

	// SECURITY (CRITICAL-2): Validate unit string to prevent injection and storage abuse.
	if err := validateDynamicUnit(rawUnit); err != nil {
		return false, fmt.Errorf("invalid dynamic budget unit: %w", err)
	}

	chainID := ""
	if rule.ChainID != nil {
		chainID = *rule.ChainID
	}
	unit := NormalizeBudgetUnit(chainID + ":" + rawUnit)

	// Look up or auto-create budget for the dynamic unit
	budget, err := bc.budgetRepo.GetByRuleID(ctx, rule.ID, unit)
	if err != nil {
		if !types.IsNotFound(err) {
			return false, fmt.Errorf("failed to get dynamic budget: %w", err)
		}
		budget, err = bc.autoCreateDynamicBudget(ctx, rule, unit, rawUnit, metering)
		if err != nil {
			return false, fmt.Errorf("failed to auto-create dynamic budget: %w", err)
		}
	}

	// Check periodic renewal
	if err := bc.checkPeriodicRenewal(ctx, rule, budget, unit); err != nil {
		return false, fmt.Errorf("failed to check periodic renewal for rule %s: %w", rule.ID, err)
	}

	// Check per-tx limit
	if budget.MaxPerTx != "" && budget.MaxPerTx != "-1" {
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

	// Atomic spend
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

// validateDynamicUnit validates the raw unit string from JS validateBudget return.
// SECURITY (CRITICAL-2): Prevents injection attacks and storage abuse via crafted unit strings.
func validateDynamicUnit(rawUnit string) error {
	if len(rawUnit) > maxUnitLength {
		return fmt.Errorf("unit string too long (%d > %d)", len(rawUnit), maxUnitLength)
	}
	if !validDynamicUnitRe.MatchString(rawUnit) {
		return fmt.Errorf("unit %q does not match allowed pattern (hex address or alphanumeric name)", rawUnit)
	}
	return nil
}

// autoCreateDynamicBudget creates a new budget record for a dynamic unit discovered at evaluation time.
// Looks up known_units config first, then falls back to unknown_default. Applies unit_decimal conversion.
//
// SECURITY (CRITICAL-2): Enforces MaxDynamicUnits to cap the number of distinct units per rule.
// SECURITY (CRITICAL-3): Uses CreateOrGet (upsert) to prevent TOCTOU race on concurrent auto-creation.
func (bc *BudgetChecker) autoCreateDynamicBudget(
	ctx context.Context,
	rule *types.Rule,
	normalizedUnit string,
	rawUnit string,
	metering types.BudgetMetering,
) (*types.RuleBudget, error) {
	// SECURITY (CRITICAL-2): Enforce max dynamic units per rule.
	maxUnits := metering.MaxDynamicUnits
	if maxUnits <= 0 {
		maxUnits = defaultMaxDynamicUnits
	}
	unitCount, err := bc.budgetRepo.CountByRuleID(ctx, rule.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to count dynamic units: %w", err)
	}
	if unitCount >= maxUnits {
		return nil, fmt.Errorf("dynamic budget unit limit reached (%d/%d) for rule %s", unitCount, maxUnits, rule.ID)
	}

	// Look up unit config: check known_units by raw unit (before chain_id prefix), then unknown_default
	var conf *types.UnitConf
	if metering.KnownUnits != nil {
		if c, ok := metering.KnownUnits[rawUnit]; ok {
			conf = &c
		} else if c, ok := metering.KnownUnits[NormalizeBudgetUnit(rawUnit)]; ok {
			conf = &c
		}
	}
	if conf == nil {
		if metering.UnknownDefault != nil {
			conf = metering.UnknownDefault
		} else {
			// SECURITY: no config for unknown unit and no default — fail-closed
			return nil, fmt.Errorf("no budget config for dynamic unit %q and no unknown_default configured", rawUnit)
		}
	}

	maxTotal := conf.MaxTotal
	maxPerTx := conf.MaxPerTx

	// unit_decimal conversion: convert human-readable limits to raw big integer
	if metering.UnitDecimal {
		decimals := conf.Decimals
		// SECURITY (MEDIUM-5): Validate decimals range to prevent overflow.
		if err := validateDecimals(decimals); err != nil {
			return nil, fmt.Errorf("invalid decimals for unit %q: %w", rawUnit, err)
		}
		if decimals <= 0 {
			// For now, fail-closed when decimals not configured and no RPC available
			// Phase 2 will add erc20.decimals() auto-query via RPC
			return nil, fmt.Errorf("unit_decimal enabled but decimals not configured for unit %q (RPC auto-query not yet implemented)", rawUnit)
		}
		var convertErr error
		maxTotal, convertErr = decimalToRaw(maxTotal, decimals)
		if convertErr != nil {
			return nil, fmt.Errorf("failed to convert max_total for unit %q: %w", rawUnit, convertErr)
		}
		if maxPerTx != "" && maxPerTx != "-1" {
			maxPerTx, convertErr = decimalToRaw(maxPerTx, decimals)
			if convertErr != nil {
				return nil, fmt.Errorf("failed to convert max_per_tx for unit %q: %w", rawUnit, convertErr)
			}
		}
	}

	alertPct := conf.AlertPct
	if alertPct <= 0 {
		alertPct = 80 // default
	}

	budget := &types.RuleBudget{
		ID:         types.BudgetID(rule.ID, normalizedUnit),
		RuleID:     rule.ID,
		Unit:       normalizedUnit,
		MaxTotal:   maxTotal,
		MaxPerTx:   maxPerTx,
		Spent:      "0",
		AlertPct:   alertPct,
		TxCount:    0,
		MaxTxCount: conf.MaxTxCount,
	}

	// SECURITY (CRITICAL-3): Use CreateOrGet to prevent TOCTOU race.
	// Concurrent requests that both find "not found" will both call this;
	// only one will actually create, the other gets the existing record.
	result, created, err := bc.budgetRepo.CreateOrGet(ctx, budget)
	if err != nil {
		return nil, fmt.Errorf("failed to create-or-get budget record: %w", err)
	}

	if created {
		bc.logger.Info("auto-created dynamic budget record",
			"rule_id", rule.ID,
			"unit", normalizedUnit,
			"raw_unit", rawUnit,
			"max_total", maxTotal,
			"max_per_tx", maxPerTx,
		)
	}

	return result, nil
}

// validateDecimals checks that decimals are within a safe range.
// SECURITY (MEDIUM-5): Reject negative decimals (possible from malicious contracts)
// and excessively large values that could cause overflow in decimal-to-raw conversion.
func validateDecimals(decimals int) error {
	if decimals < 0 {
		return fmt.Errorf("negative decimals (%d) not allowed", decimals)
	}
	if decimals > maxDecimalDigits {
		return fmt.Errorf("decimals %d exceeds maximum %d", decimals, maxDecimalDigits)
	}
	return nil
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
	// Skip when no cap (-1), not set (""), or cap is 0 (no meaningful percentage)
	if budget.AlertSent || budget.AlertPct <= 0 || budget.MaxTotal == "" || budget.MaxTotal == "-1" || budget.MaxTotal == "0" {
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
	for k, v := range raw {
		if v == nil {
			continue
		}
		unit = strings.ReplaceAll(unit, "${"+k+"}", fmt.Sprintf("%v", v))
	}
	return unit
}
