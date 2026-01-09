package storage

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Config holds database configuration
type Config struct {
	DSN string `yaml:"dsn"`
}

// NewDB creates a new database connection with auto-migration
func NewDB(cfg Config) (*gorm.DB, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("database DSN is required")
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{
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
		&types.APIKey{},
		&types.AuditRecord{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	return db, nil
}

// NewDBWithLogger creates a new database connection with custom logger
func NewDBWithLogger(cfg Config, logLevel logger.LogLevel) (*gorm.DB, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("database DSN is required")
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.AutoMigrate(
		&types.SignRequest{},
		&types.Rule{},
		&types.APIKey{},
		&types.AuditRecord{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	return db, nil
}
