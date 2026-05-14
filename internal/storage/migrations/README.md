# SQL migrations (golang-migrate)

Versioned SQL migrations run after GORM AutoMigrate. All migration SQL lives here.

## Layout

- `postgres/` – migrations for PostgreSQL (e.g. `ALTER COLUMN`, `CREATE INDEX`)
- `sqlite/` – migrations for SQLite (same version numbers; use no-ops or SQLite-compatible DDL where needed)

Same version number in both dirs (e.g. `000001_...`) keeps ordering in sync.

## Naming

- `{version}_{name}.up.sql` – apply migration
- `{version}_{name}.down.sql` – revert (optional but recommended)

Version = integer (e.g. 000001, 000002). Name = short snake_case description.

## Adding a migration

1. Add `000002_my_change.up.sql` and `000002_my_change.down.sql` under both `postgres/` and `sqlite/`.
2. For SQLite: use a no-op (e.g. `SELECT 1;`) if the change is Postgres-only.
3. Run tests: `go test ./internal/storage/... -run TestRunMigrations`

## How it runs

On startup, `storage.NewDB` / `NewDBWithLogger` run GORM AutoMigrate, then `runMigrations(db, dsn)` which uses embedded SQL from this directory and applies pending migrations. Applied versions are stored in `schema_migrations` (golang-migrate default).
