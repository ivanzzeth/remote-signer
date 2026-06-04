package storage

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// repairLegacyTimestamps normalizes datetime columns that were written using
// Go's String() format (with monotonic suffix) into UTC RFC3339Nano strings
// that GORM can round-trip. Idempotent — safe to run on every startup.
func repairLegacyTimestamps(db *gorm.DB) error {
	if err := repairTableTimestamps(db, "rule_budgets", []string{"created_at", "updated_at"}); err != nil {
		return fmt.Errorf("rule_budgets: %w", err)
	}
	if err := repairTableTimestamps(db, "rules", []string{"created_at", "updated_at", "budget_period_start", "expires_at", "last_matched_at"}); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	return nil
}

func repairTableTimestamps(db *gorm.DB, table string, columns []string) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	for _, col := range columns {
		query := fmt.Sprintf(
			"SELECT rowid, CAST(%s AS TEXT) FROM %s WHERE %s IS NOT NULL AND %s != ''",
			col, table, col, col,
		)
		rows, err := sqlDB.QueryContext(context.Background(), query)
		if err != nil {
			return err
		}
		type pendingRepair struct {
			rowid int64
			value string
		}
		var pending []pendingRepair
		for rows.Next() {
			var rowid int64
			var raw string
			if err := rows.Scan(&rowid, &raw); err != nil {
				rows.Close()
				return err
			}
			if raw == "" || isRFC3339Stored(raw) {
				continue
			}
			parsed, err := parseDBTime(raw)
			if err != nil || parsed.IsZero() {
				continue
			}
			formatted := formatDBTime(parsed)
			if formatted == raw {
				continue
			}
			pending = append(pending, pendingRepair{rowid: rowid, value: formatted})
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, item := range pending {
			if err := db.Exec(
				fmt.Sprintf("UPDATE %s SET %s = ? WHERE rowid = ?", table, col),
				item.value, item.rowid,
			).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func isRFC3339Stored(s string) bool {
	return len(s) >= 20 && s[4] == '-' && s[7] == '-' && s[10] == 'T'
}
