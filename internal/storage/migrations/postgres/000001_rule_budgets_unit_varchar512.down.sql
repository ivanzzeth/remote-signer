-- Revert rule_budgets.unit to varchar(64). Only safe if no data exceeds 64 chars.
ALTER TABLE rule_budgets ALTER COLUMN unit TYPE varchar(64);
