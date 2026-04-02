package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestRunMigrations_AppliedOnce(t *testing.T) {
	// Use a temp file DB because golang-migrate opens its own connection,
	// which cannot share an in-memory database with GORM.
	dbPath := filepath.Join(t.TempDir(), "test_migrate.db")
	dsn := dbPath
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleBudget{}))
	t.Cleanup(func() { os.Remove(dbPath) })

	// First run: migration 000001 applies and is recorded in schema_migrations
	err = runMigrations(db, dsn)
	require.NoError(t, err)

	var version uint
	row := db.Raw("SELECT version FROM schema_migrations LIMIT 1").Row()
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&version))
	assert.Equal(t, uint(2), version, "migration version 2 should be recorded")

	// Second run: idempotent (ErrNoChange), no error
	err = runMigrations(db, dsn)
	require.NoError(t, err)
}
