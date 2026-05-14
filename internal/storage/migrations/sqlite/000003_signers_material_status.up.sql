CREATE TABLE IF NOT EXISTS signers (
    address TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    primary_address TEXT NOT NULL,
    hd_derivation_index INTEGER NULL,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    locked BOOLEAN NOT NULL DEFAULT 0,
    material_status TEXT NOT NULL DEFAULT 'present',
    material_checked_at DATETIME NULL,
    material_missing_at DATETIME NULL,
    material_error TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_signers_type ON signers(type);
CREATE INDEX IF NOT EXISTS idx_signers_primary_address ON signers(primary_address);
CREATE INDEX IF NOT EXISTS idx_signers_locked ON signers(locked);
CREATE INDEX IF NOT EXISTS idx_signers_material_status ON signers(material_status);
