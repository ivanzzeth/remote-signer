package types

import "time"

// SignerOwnershipStatus represents the status of signer ownership.
type SignerOwnershipStatus string

const (
	SignerOwnershipActive          SignerOwnershipStatus = "active"
	SignerOwnershipPendingApproval SignerOwnershipStatus = "pending_approval"
)

// SignerOwnership tracks which API key owns a signer address.
// Signers live in-memory (ethsig Registry), so this table provides
// persistent ownership metadata keyed by address.
type SignerOwnership struct {
	SignerAddress string                `json:"signer_address" gorm:"primaryKey;type:varchar(42)"`
	OwnerID       string                `json:"owner_id" gorm:"type:varchar(64);not null;index"`
	Status        SignerOwnershipStatus `json:"status" gorm:"type:varchar(20);not null;default:'active'"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

// TableName specifies the table name for GORM.
func (SignerOwnership) TableName() string {
	return "signer_ownership"
}

// SignerAccess grants an API key access to a signer that it does not own.
type SignerAccess struct {
	ID            string    `json:"id" gorm:"primaryKey;type:varchar(128)"`
	SignerAddress string    `json:"signer_address" gorm:"type:varchar(42);not null;uniqueIndex:idx_signer_access_addr_key"`
	APIKeyID      string    `json:"api_key_id" gorm:"type:varchar(64);not null;uniqueIndex:idx_signer_access_addr_key"`
	GrantedBy     string    `json:"granted_by" gorm:"type:varchar(64);not null"`
	CreatedAt     time.Time `json:"created_at"`
}

// TableName specifies the table name for GORM.
func (SignerAccess) TableName() string {
	return "signer_access"
}
