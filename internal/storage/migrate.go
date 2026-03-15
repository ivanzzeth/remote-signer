package storage

import (
	"embed"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"
)

// Embed dialect-specific migrations. Use runMigrations with the appropriate subdir.
//
//go:embed migrations/postgres/*.sql migrations/sqlite/*.sql
var embedMigrations embed.FS

// runMigrations runs pending SQL migrations from the embedded migrations directory.
// Dialect must be "postgres" or "sqlite"/"sqlite3". DSN is the same as GORM; it is
// converted to the format expected by golang-migrate (e.g. sqlite3:// for SQLite).
func runMigrations(db *gorm.DB, dsn string) error {
	dialector := db.Dialector.Name()
	var migrateURL string
	var embedPath string
	switch dialector {
	case "postgres":
		migrateURL = dsn
		embedPath = "migrations/postgres"
	case "sqlite", "sqlite3":
		// golang-migrate sqlite3 driver expects "sqlite3://..." or "file://..."
		if strings.HasPrefix(dsn, "file:") {
			migrateURL = "sqlite3://" + dsn
		} else {
			migrateURL = "sqlite3://" + dsn
		}
		embedPath = "migrations/sqlite"
	default:
		return fmt.Errorf("unsupported dialect for migrations: %s", dialector)
	}

	src, err := iofs.New(embedMigrations, embedPath)
	if err != nil {
		return fmt.Errorf("migration source: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, migrateURL)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}
