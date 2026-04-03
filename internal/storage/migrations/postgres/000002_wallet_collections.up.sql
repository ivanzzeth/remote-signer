-- Add wallet_id column to signer_access for linking access grants to wallets.
-- Nullable: existing rows have no wallet_id (direct signer-level access).
ALTER TABLE signer_access ADD COLUMN IF NOT EXISTS wallet_id VARCHAR(255);

-- Index for looking up access grants by wallet_id.
CREATE INDEX IF NOT EXISTS idx_signer_access_wallet_id ON signer_access(wallet_id);

-- Index for looking up wallet members by wallet_id (reverse lookup).
CREATE INDEX IF NOT EXISTS idx_wallet_members_wallet_id ON wallet_members(wallet_id);

-- Index for looking up wallets by owner.
CREATE INDEX IF NOT EXISTS idx_wallets_owner_id ON wallets(owner_id);
