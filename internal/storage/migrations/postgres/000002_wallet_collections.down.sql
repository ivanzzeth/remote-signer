-- Revert wallet migration.
DROP INDEX IF EXISTS idx_wallets_owner_id;
DROP INDEX IF EXISTS idx_wallet_members_wallet_id;
DROP INDEX IF EXISTS idx_signer_access_wallet_id;
ALTER TABLE signer_access DROP COLUMN IF EXISTS wallet_id;
