package types

import "time"

// RuleBudget tracks spending limits for a rule instance.
// Each rule can have one budget per unit (e.g., "usdt", "eth").
// Unique constraint: (RuleID, Unit)
type RuleBudget struct {
	ID         string    `json:"id" gorm:"primaryKey;type:varchar(64)"`
	RuleID     RuleID    `json:"rule_id" gorm:"index;type:varchar(64)"`
	Unit       string    `json:"unit" gorm:"type:varchar(64)"`
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
