package storage

import (
	"fmt"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// detectDialector returns the appropriate GORM dialector based on DSN format
func detectDialector(dsn string) (gorm.Dialector, error) {
	// SQLite: starts with "file:" or ends with ".db"
	if strings.HasPrefix(dsn, "file:") || strings.HasSuffix(dsn, ".db") {
		return sqlite.Open(dsn), nil
	}

	// PostgreSQL: starts with "postgres://" or "postgresql://"
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return postgres.Open(dsn), nil
	}

	// Default: try PostgreSQL for backward compatibility
	return postgres.Open(dsn), nil
}

// Config holds database configuration
type Config struct {
	DSN string `yaml:"dsn"`
}

// NewDB creates a new database connection with auto-migration
func NewDB(cfg Config) (*gorm.DB, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("database DSN is required")
	}

	dialector, err := detectDialector(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to detect database type: %w", err)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate all models (backward-compatible schema changes only)
	// Rules for schema evolution:
	// - Only ADD columns (never remove)
	// - New columns must be nullable or have defaults
	// - Never change column types incompatibly
	if err := db.AutoMigrate(
		&types.SignRequest{},
		&types.Rule{},
		&types.RuleTemplate{},
		&types.RuleBudget{},
		&types.APIKey{},
		&types.AuditRecord{},
		&types.TokenMetadata{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	// Run versioned SQL migrations (e.g. widen columns) from internal/storage/migrations/<dialect>/
	if err := runMigrations(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}

	return db, nil
}

// NewDBWithLogger creates a new database connection with custom logger
func NewDBWithLogger(cfg Config, logLevel logger.LogLevel) (*gorm.DB, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("database DSN is required")
	}

	dialector, err := detectDialector(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to detect database type: %w", err)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.AutoMigrate(
		&types.SignRequest{},
		&types.Rule{},
		&types.RuleTemplate{},
		&types.RuleBudget{},
		&types.APIKey{},
		&types.AuditRecord{},
		&types.TokenMetadata{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	if err := runMigrations(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}

	return db, nil
}
