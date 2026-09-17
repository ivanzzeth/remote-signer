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

	// ⛔ journal_mode 与 busy_timeout 必须在这里设,**不能指望 DSN**。
	//
	// 配置里写的是 `?_journal_mode=WAL&_busy_timeout=5000` —— 那是
	// **mattn/go-sqlite3 的参数格式**,而这里用的是 modernc.org/sqlite
	// (为了 CGO_ENABLED=0,理由见文件顶部的 import 注释)。modernc 不认那种写法,
	// 它认的是 `_pragma=journal_mode(WAL)`。三种写法实测:
	//
	//   _journal_mode=WAL&_busy_timeout=5000  → journal_mode=delete, busy_timeout=0
	//   _pragma=journal_mode(WAL)             → journal_mode=wal,    busy_timeout=5000
	//   (什么参数都不写)                        → journal_mode=delete, busy_timeout=0
	//
	// ⚠️ 也就是说现用的 DSN 参数与「什么都不写」**逐字等价**,静默无效了很久。
	// 后果是两条,都与配置文件写的相反:库跑在 rollback 模式(一次写独占整个库,
	// 连读都被挡在外面,而 WAL 下读写可并发),且 busy_timeout=0 —— 撞锁**立即
	// 失败,一秒都不等**。
	//
	// ⭐ 它露头的地方是 e2e:CI 上 web-e2e 长期 10 个用例红,报错五花八门
	// (cannot start a transaction within a transaction / no ownership record /
	// element(s) not found),底下其实是同一件事换了马甲。⚠️ 本地 141 个全绿 ——
	// 连 taskset 锁到 2 核也全绿 —— 因为 NVMe 上写事务快到锁几乎不持有;
	// CI 的慢磁盘只是把同一个隐患的窗口放大了。⛔ 所以这不是「CI 环境问题」。
	//
	// ⚠️ 为什么修这里而不是改 DSN 字符串:PRAGMA 走 Exec 与驱动无关,将来换驱动
	// 不会再次静默归零;而 DSN 参数格式是驱动私有约定,换一个驱动就又悄悄失效,
	// 且失效时**没有任何报错** —— 正是它能潜伏这么久的原因。
	if err := db.Exec("PRAGMA journal_mode = WAL").Error; err != nil {
		return fmt.Errorf("enable WAL journal mode: %w", err)
	}
	// ⚠️ 这里写死 5000,与现有配置里那个从未生效过的数字一致。让 DSN 里用户写的
	// 值真正可配置是**另一件事**(要连 config 层一起改),⛔ 不在这次改动里 ——
	// 先让「配置里要的两件事成立」,别夹带。
	if err := db.Exec("PRAGMA busy_timeout = 5000").Error; err != nil {
		return fmt.Errorf("set busy_timeout pragma: %w", err)
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

// NewDB opens the database with logging silenced, which is what every caller
// outside the CLI's verbose mode wants.
//
// ⚠️ This was a 50-line copy of NewDBWithLogger differing in one argument —
// logger.Silent instead of the caller's level. Everything else was the same
// sequence of steps: detect dialect, open, tune the pool, auto-migrate, run
// versioned migrations, backfill foreign keys, repair legacy timestamps. A
// migration step added to one and not the other is a database that is set up
// differently depending on which constructor the binary happened to call.
func NewDB(cfg Config) (*gorm.DB, error) {
	return NewDBWithLogger(cfg, logger.Silent)
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

	// Versioned SQL migrations (e.g. widen columns) from
	// internal/storage/migrations/<dialect>/
	if err := runMigrations(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}

	// Backfill FK constraints on existing SQLite databases. GORM's AutoMigrate
	// leaves existing tables untouched and only adds FKs on fresh CREATE TABLE
	// statements. ensureForeignKeys recreates tables that are missing their FK,
	// matching what the GORM struct tags declare. Postgres handles this via
	// standard ALTER TABLE ADD CONSTRAINT migration files.
	if err := ensureForeignKeys(db, cfg.DSN); err != nil {
		return nil, fmt.Errorf("ensure foreign keys: %w", err)
	}

	if err := repairLegacyTimestamps(db); err != nil {
		return nil, fmt.Errorf("repair legacy timestamps: %w", err)
	}

	return db, nil
}

// AutoMigrate creates or updates every table this daemon owns.
//
// Exported so test harnesses migrate exactly what production migrates. The e2e
// harness kept its own hand-copied list and it had drifted by four tables —
// Transaction, RequestSimulation, Signer and settings.Setting. A missing table
// does not fail at startup; it fails at the first query, as
// "no such table: system_settings" deep inside a feature, which is how the
// approval-guard endpoint came to answer 501 in e2e and nowhere else.
//
// ⛔ Add new models here, never in a second list.
func AutoMigrate(db *gorm.DB) error { return autoMigrate(db) }

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
