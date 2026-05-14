-- No-op for SQLite. GORM AutoMigrate creates all tables, columns, and basic indexes.
-- The Postgres migration adds explicit indexes; SQLite relies on AutoMigrate.
SELECT 1;
