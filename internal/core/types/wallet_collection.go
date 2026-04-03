package types

import (
	"time"
)

// Wallet groups signers under a named container.
// Wallets are explicit organizational entities and are distinct from signers.
type Wallet struct {
	ID          string    `json:"id" gorm:"primaryKey;type:varchar(36)"`
	Name        string    `json:"name" gorm:"type:varchar(255);not null"`
	Description string    `json:"description" gorm:"type:text"`
	OwnerID     string    `json:"owner_id" gorm:"type:varchar(64);not null;index"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TableName specifies the table name for GORM.
func (Wallet) TableName() string {
	return "wallets"
}

// WalletMember links a signer address to a wallet.
type WalletMember struct {
	WalletID      string    `json:"wallet_id" gorm:"primaryKey;type:varchar(36)"`
	SignerAddress string    `json:"signer_address" gorm:"primaryKey;type:varchar(255)"`
	AddedAt       time.Time `json:"added_at"`
}

// TableName specifies the table name for GORM.
func (WalletMember) TableName() string {
	return "wallet_members"
}

// WalletFilter defines filter options for listing wallets.
type WalletFilter struct {
	OwnerID string
	Offset  int
	Limit   int
}

// WalletListResult contains paginated wallet list result.
type WalletListResult struct {
	Wallets []Wallet
	Total       int
	HasMore     bool
}
