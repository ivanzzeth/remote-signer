package types

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"time"
)

// RuleBudget tracks spending limits for a rule instance.
// Each rule can have one budget per unit (e.g., "usdt", "eth").
// Unique constraint: (RuleID, Unit)
type RuleBudget struct {
	ID         string    `json:"id" gorm:"primaryKey;type:varchar(64)"` // SHA256 hex of (ruleID, unit) via BudgetID()
	RuleID     RuleID    `json:"rule_id" gorm:"index;type:varchar(64)"`
	Unit       string    `json:"unit" gorm:"type:varchar(512)"` // 256*2: safe limit, supports chain_id:address:uint256_hex etc.
	MaxTotal   string    `json:"max_total" gorm:"type:varchar(128)"`           // max total spend per period (or lifetime if no schedule)
	MaxPerTx   string    `json:"max_per_tx" gorm:"type:varchar(128)"`          // max spend per transaction
	Spent      string    `json:"spent" gorm:"type:varchar(128);default:'0'"`   // current period spend
	AlertPct   int       `json:"alert_pct" gorm:"default:80"`                  // alert threshold percentage
	AlertSent  bool      `json:"alert_sent" gorm:"default:false"`              // whether alert was sent this period
	TxCount    int       `json:"tx_count" gorm:"default:0"`                    // transactions in current period
	MaxTxCount int       `json:"max_tx_count" gorm:"default:0"`                // 0 = unlimited
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// TableName specifies the table name for GORM
func (RuleBudget) TableName() string {
	return "rule_budgets"
}

// BudgetResult is returned by JS validateBudget when dynamic budget is enabled.
// It carries both the spend amount and the dynamic unit string.
// When Unit is empty, the static unit from BudgetMetering is used (backward compatible).
type BudgetResult struct {
	Amount *big.Int
	Unit   string // dynamic unit from JS; empty means use static unit
}

// BudgetID returns a deterministic 64-char id for (ruleID, unit) so it fits varchar(64).
// Uses SHA256 hex; same (ruleID, unit) always yields the same id.
func BudgetID(ruleID RuleID, unit string) string {
	h := sha256.Sum256([]byte(string(ruleID) + "\x00" + unit))
	return hex.EncodeToString(h[:])
}
