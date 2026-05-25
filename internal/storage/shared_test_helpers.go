package storage

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// newIntegrationDB creates an isolated in-memory SQLite DB with all models
// auto-migrated. Each test gets its own DB via t.Name() so parallel tests
// don't share state.
func newIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.Signer{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
		&types.RulePreset{},
		&types.Transaction{},
		&types.Rule{},
		&types.RuleTemplate{},
		&types.RuleBudget{},
		&types.AuditRecord{},
		&types.RequestSimulation{},
		&types.SignRequest{},
	))
	return db
}
