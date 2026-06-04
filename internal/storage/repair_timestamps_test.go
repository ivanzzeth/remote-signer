package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRepairLegacyTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repair.db")
	db, err := gorm.Open(sqlite.Open("file:"+path+"?_journal_mode=WAL"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.Exec(`
		CREATE TABLE rule_budgets (
			rowid INTEGER PRIMARY KEY AUTOINCREMENT,
			updated_at TEXT NOT NULL
		)
	`).Error)
	legacy := "2026-06-02 00:15:42.690163069 +0800 CST m=+1815.275862388"
	require.NoError(t, db.Exec("INSERT INTO rule_budgets (updated_at) VALUES (?)", legacy).Error)

	require.NoError(t, repairTableTimestamps(db, "rule_budgets", []string{"updated_at"}))

	var got string
	require.NoError(t, db.Raw("SELECT updated_at FROM rule_budgets LIMIT 1").Scan(&got).Error)
	require.True(t, isRFC3339Stored(got), "expected RFC3339, got %q", got)
}
