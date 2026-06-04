package storage

import (
	"fmt"
	"strings"
	"time"

	// Pure-Go SQLite driver. Registers under database/sql name "sqlite", which
	// detectDialector passes to gorm.io/driver/sqlite via Config.DriverName so
	// CGO_ENABLED=0 release builds can still open SQLite databases. mattn/go-sqlite3
	// (gorm.io/driver/sqlite's default) requires CGO and would block single-instance
	// deployment of the release binary.
	_ "modernc.org/sqlite"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// sqliteDriverName matches the name modernc.org/sqlite registers with database/sql.
const sqliteDriverName = "sqlite"

// tuneSQLite applies engine-specific pool settings and enables foreign keys.
func tuneSQLite(db *gorm.DB, dsn string) error {
	if !strings.HasPrefix(dsn, "file:") && !strings.HasSuffix(dsn, ".db") {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	// SQLite disables foreign keys by default. GORM's constraint tag
	// (OnDelete:CASCADE) has no effect unless foreign_keys PRAGMA is ON.
	if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		return fmt.Errorf("enable foreign_keys pragma: %w", err)
	}
	return nil
}

// detectDialector returns the appropriate GORM dialector based on DSN format.
// For SQLite, the pure-Go modernc.org/sqlite driver is selected explicitly so
// CGO-disabled builds work; mattn/go-sqlite3 is intentionally not used.
func detectDialector(dsn string) (gorm.Dialector, error) {
	// SQLite: starts with "file:" or ends with ".db"
	if strings.HasPrefix(dsn, "file:") || strings.HasSuffix(dsn, ".db") {
		return sqlite.New(sqlite.Config{DSN: dsn, DriverName: sqliteDriverName}), nil
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
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := tuneSQLite(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("failed to tune connection pool: %w", err)
	}

	if err := autoMigrate(db); err != nil {
		return nil, err
	}

	// Run versioned SQL migrations (e.g. widen columns) from internal/storage/migrations/<dialect>/
	if err := runMigrations(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}

	// Backfill FK constraints on existing SQLite databases. GORM's
	// AutoMigrate leaves existing tables untouched and only adds FKs on
	// fresh CREATE TABLE statements. ensureForeignKeys recreates tables
	// that are missing their FK, matching what the GORM struct tags
	// declare. Postgres handles this via standard ALTER TABLE ADD
	// CONSTRAINT migration files.
	if err := ensureForeignKeys(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("ensure foreign keys: %w", err)
	}

	if err := repairLegacyTimestamps(db); err != nil {
		return nil, fmt.Errorf("repair legacy timestamps: %w", err)
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
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := tuneSQLite(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("failed to tune connection pool: %w", err)
	}

	if err := autoMigrate(db); err != nil {
		return nil, err
	}

	if err := runMigrations(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}

	if err := ensureForeignKeys(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("ensure foreign keys: %w", err)
	}

	if err := repairLegacyTimestamps(db); err != nil {
		return nil, fmt.Errorf("repair legacy timestamps: %w", err)
	}

	return db, nil
}

func autoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&types.SignRequest{},
		&types.Transaction{},
		&types.RequestSimulation{},
		&types.Rule{},
		&types.RuleTemplate{},
		&types.RulePreset{},
		&types.RuleBudget{},
		&types.APIKey{},
		&types.AuditRecord{},
		&types.TokenMetadata{},
		&types.Signer{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
		&types.Wallet{},
		&types.WalletMember{},
		&settings.Setting{},
	); err != nil {
		return fmt.Errorf("failed to auto-migrate: %w", err)
	}
	return nil
}
