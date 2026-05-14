-- Widen rule_budgets.unit from varchar(64) to varchar(512) for long units (e.g. chain_id:address:uint256_hex).
-- Backward-compatible; safe to run when column is already 512.
ALTER TABLE rule_budgets ALTER COLUMN unit TYPE varchar(512);
