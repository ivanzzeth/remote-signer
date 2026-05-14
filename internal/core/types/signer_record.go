package types

import "time"

// SignerMaterialStatus indicates local key material availability.
type SignerMaterialStatus string

const (
	SignerMaterialStatusPresent   SignerMaterialStatus = "present"
	SignerMaterialStatusMissing   SignerMaterialStatus = "missing"
	SignerMaterialStatusCorrupted SignerMaterialStatus = "corrupted"
)

// Signer is the DB-backed signer inventory/read model.
// This table is the authoritative source for signer listing metadata.
type Signer struct {
	Address           string               `json:"address" gorm:"primaryKey;type:varchar(42)"`
	Type              SignerType           `json:"type" gorm:"type:varchar(20);not null;index"`
	PrimaryAddress    string               `json:"primary_address" gorm:"type:varchar(42);not null;index"`
	HDDerivationIndex *uint32              `json:"hd_derivation_index,omitempty"`
	Enabled           bool                 `json:"enabled" gorm:"not null;default:true"`
	Locked            bool                 `json:"locked" gorm:"not null;default:false;index"`
	MaterialStatus    SignerMaterialStatus `json:"material_status" gorm:"type:varchar(20);not null;default:'present';index"`
	MaterialCheckedAt *time.Time           `json:"material_checked_at,omitempty"`
	MaterialMissingAt *time.Time           `json:"material_missing_at,omitempty"`
	MaterialError     string               `json:"material_error,omitempty" gorm:"type:text"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
}

// TableName specifies the table name for GORM.
func (Signer) TableName() string {
	return "signers"
}
