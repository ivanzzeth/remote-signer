-- Revert wallet_collections migration.
DROP INDEX IF EXISTS idx_wallet_collections_owner_id;
DROP INDEX IF EXISTS idx_collection_members_wallet_id;
DROP INDEX IF EXISTS idx_signer_access_wallet_id;
ALTER TABLE signer_access DROP COLUMN IF EXISTS wallet_id;
