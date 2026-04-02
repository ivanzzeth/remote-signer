-- Add wallet_id column to signer_access for linking access grants to wallets/collections.
-- Nullable: existing rows have no wallet_id (direct signer-level access).
ALTER TABLE signer_access ADD COLUMN IF NOT EXISTS wallet_id VARCHAR(255);

-- Index for looking up access grants by wallet_id.
CREATE INDEX IF NOT EXISTS idx_signer_access_wallet_id ON signer_access(wallet_id);

-- Index for looking up collection members by wallet_id (reverse lookup).
CREATE INDEX IF NOT EXISTS idx_collection_members_wallet_id ON collection_members(wallet_id);

-- Index for looking up collections by owner.
CREATE INDEX IF NOT EXISTS idx_wallet_collections_owner_id ON wallet_collections(owner_id);
