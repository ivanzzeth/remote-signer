package types

import (
	"time"
)

// WalletCollection groups wallets (keystores, HD wallets, or other collections) under a named collection.
// Collections enable batch access control: granting access to a collection grants access to all its members.
type WalletCollection struct {
	ID          string    `json:"id" gorm:"primaryKey;type:varchar(36)"`
	Name        string    `json:"name" gorm:"type:varchar(255);not null"`
	Description string    `json:"description" gorm:"type:text"`
	OwnerID     string    `json:"owner_id" gorm:"type:varchar(64);not null;index"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TableName specifies the table name for GORM.
func (WalletCollection) TableName() string {
	return "wallet_collections"
}

// CollectionMember links a wallet_id to a collection.
// wallet_id can reference a keystore address, HD wallet primary address, or another collection ID.
type CollectionMember struct {
	CollectionID string    `json:"collection_id" gorm:"primaryKey;type:varchar(36)"`
	WalletID     string    `json:"wallet_id" gorm:"primaryKey;type:varchar(255)"`
	AddedAt      time.Time `json:"added_at"`
}

// TableName specifies the table name for GORM.
func (CollectionMember) TableName() string {
	return "collection_members"
}

// CollectionFilter defines filter options for listing collections.
type CollectionFilter struct {
	OwnerID string
	Offset  int
	Limit   int
}

// CollectionListResult contains paginated collection list result.
type CollectionListResult struct {
	Collections []WalletCollection
	Total       int
	HasMore     bool
}
