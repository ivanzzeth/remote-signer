CREATE TABLE IF NOT EXISTS signers (
    address VARCHAR(42) PRIMARY KEY,
    type VARCHAR(20) NOT NULL,
    primary_address VARCHAR(42) NOT NULL,
    hd_derivation_index BIGINT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    locked BOOLEAN NOT NULL DEFAULT FALSE,
    material_status VARCHAR(20) NOT NULL DEFAULT 'present',
    material_checked_at TIMESTAMPTZ NULL,
    material_missing_at TIMESTAMPTZ NULL,
    material_error TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signers_type ON signers(type);
CREATE INDEX IF NOT EXISTS idx_signers_primary_address ON signers(primary_address);
CREATE INDEX IF NOT EXISTS idx_signers_locked ON signers(locked);
CREATE INDEX IF NOT EXISTS idx_signers_material_status ON signers(material_status);
