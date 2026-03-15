package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestRunMigrations_AppliedOnce(t *testing.T) {
	// Use shared in-memory DB so GORM and migrate see the same database
	dsn := "file::memory:?cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleBudget{}))

	// First run: migration 000001 applies (SQLite no-op) and is recorded in schema_migrations
	err = runMigrations(db, dsn)
	require.NoError(t, err)

	var version uint
	row := db.Raw("SELECT version FROM schema_migrations LIMIT 1").Row()
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&version))
	assert.Equal(t, uint(1), version, "migration version 1 should be recorded")

	// Second run: idempotent (ErrNoChange), no error
	err = runMigrations(db, dsn)
	require.NoError(t, err)
}
