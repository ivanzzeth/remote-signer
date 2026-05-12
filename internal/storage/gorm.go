package storage

import (
	"fmt"
	"strings"

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

// tuneConnectionPool applies engine-specific pool settings. SQLite is
// single-writer at the file level; modernc.org/sqlite under concurrent
// gorm.Save / Transaction calls reports
// "cannot start a transaction within a transaction" when two goroutines
// share a connection that is mid-tx. Capping MaxOpenConns to 1 serialises
// the writer and matches the single-instance deployment model the binary
// is built for. Postgres deployments keep gorm's defaults.
func tuneConnectionPool(db *gorm.DB, dsn string) error {
	if !strings.HasPrefix(dsn, "file:") && !strings.HasSuffix(dsn, ".db") {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
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
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := tuneConnectionPool(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("failed to tune connection pool: %w", err)
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
		&types.Signer{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
		&types.Wallet{},
		&types.WalletMember{},
		&settings.Setting{},
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

	if err := tuneConnectionPool(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("failed to tune connection pool: %w", err)
	}

	if err := db.AutoMigrate(
		&types.SignRequest{},
		&types.Rule{},
		&types.RuleTemplate{},
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
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	if err := runMigrations(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}

	return db, nil
}
