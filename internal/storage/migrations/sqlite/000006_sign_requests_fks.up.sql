-- FK constraints on sign_requests are handled by GORM AutoMigrate via
-- struct tags (constraint:OnDelete:RESTRICT / constraint:OnDelete:SET NULL).
-- Fresh DBs get them from AutoMigrate; existing DBs need them applied from
-- within a GORM session where both the source and target tables exist.
-- This migration is a placeholder to record version 6.
SELECT 1;
