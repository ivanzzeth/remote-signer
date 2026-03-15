# Database migrations

This document describes the database migration approach used in this project. Use it as a reference when adding or changing migrations.

## Overview

- **GORM AutoMigrate**: Handles additive schema changes (create tables, add columns) from model structs.
- **golang-migrate**: Handles versioned SQL migrations (change column types, add indexes, data backfills). All migration SQL lives in a single directory and is applied in version order.

At startup the order is: **GORM AutoMigrate first, then migrate’s `Up()`**.

## Migration layout

- **Root**: `internal/storage/migrations/`
- **Per-dialect subdirs** (PostgreSQL and SQLite use different DDL, so we keep separate SQL):
  - `postgres/` – PostgreSQL-only SQL (e.g. `ALTER COLUMN`)
  - `sqlite/` – SQLite-only SQL (can be a no-op like `SELECT 1;` when the change is Postgres-only)

The same version number must exist in both subdirs so migration order stays in sync.

## File naming

Follow golang-migrate conventions:

- **Up**: `{version}_{name}.up.sql`
- **Down**: `{version}_{name}.down.sql`

Where:
- `version`: numeric, zero-padded (e.g. `000001`, `000002`) for ordering.
- `name`: short snake_case description (e.g. `rule_budgets_unit_varchar512`).

Example:

```text
internal/storage/migrations/
  postgres/
    000001_rule_budgets_unit_varchar512.up.sql
    000001_rule_budgets_unit_varchar512.down.sql
  sqlite/
    000001_rule_budgets_unit_varchar512.up.sql
    000001_rule_budgets_unit_varchar512.down.sql
```

## How migrations run

- **Entry point**: In `internal/storage/gorm.go`, `NewDB` and `NewDBWithLogger` call `runMigrations(db, cfg.DSN)` after GORM AutoMigrate.
- **Implementation**: `internal/storage/migrate.go` embeds `migrations/postgres/*.sql` and `migrations/sqlite/*.sql` via `//go:embed`, detects dialect from the DSN, and uses the matching subdir as the migrate source to run `m.Up()`.
- **State**: Applied versions are stored in the default `schema_migrations` table created by golang-migrate.

## Adding a new migration

1. **Pick the next version number**  
   e.g. if the latest is `000001`, add `000002`.

2. **Add a pair of files per dialect**  
   - Under `internal/storage/migrations/postgres/` add:
     - `000002_short_description.up.sql`
     - `000002_short_description.down.sql`
   - Under `internal/storage/migrations/sqlite/` add the same names. If the change is Postgres-only, use a no-op in SQLite, e.g.:
     ```sql
     -- No-op for SQLite.
     SELECT 1;
     ```

3. **Verify locally**  
   Run: `go test ./internal/storage/... -run TestRunMigrations`  
   to ensure the migration runs and the version is recorded.

4. **Deploy**  
   On startup, any pending migrations are applied automatically; no extra scripts are required.

## Division of responsibility (GORM vs migrate)

| Change type              | Use                         | Notes |
|--------------------------|-----------------------------|--------|
| New tables, new columns  | GORM AutoMigrate            | Update the model; AutoMigrate adds tables/columns |
| Change column type/size  | migrate `.up.sql`           | AutoMigrate does not alter existing columns |
| Add index, change constraint | migrate `.up.sql`       | Versioned and reversible |
| Data backfills           | migrate `.up.sql`           | Versioned and repeatable |

## Backward compatibility and existing DBs

- **Existing databases** (e.g. already on main, or previously updated with schema_patches):  
  On first startup with the migrate-based code, all pending migrations run. If a migration is effectively already applied (e.g. column already the target type), re-running the same ALTER is usually safe/idempotent on PostgreSQL.

- **New databases**:  
  AutoMigrate creates tables (with current model, e.g. varchar(512)); then migrate runs. Running a migration that matches the current schema is still safe.

## References

- Option comparison and rationale: `docs/architecture/database-migrations-research.md`
- Short README in the migrations tree: `internal/storage/migrations/README.md`
- Dependency: [golang-migrate/migrate](https://github.com/golang-migrate/migrate)
