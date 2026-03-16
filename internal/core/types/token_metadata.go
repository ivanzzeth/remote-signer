package types

import "time"

// TokenMetadata stores cached on-chain token/contract info queried via RPC.
// Lives in core/types so storage layer can reference it without importing chain/evm.
type TokenMetadata struct {
	ChainID   string    `gorm:"primaryKey;column:chain_id" json:"chain_id"`
	Address   string    `gorm:"primaryKey;column:address" json:"address"` // checksummed
	Decimals  *int      `gorm:"column:decimals" json:"decimals,omitempty"`
	Symbol    *string   `gorm:"column:symbol" json:"symbol,omitempty"`
	Name      *string   `gorm:"column:name" json:"name,omitempty"`
	IsERC721  bool      `gorm:"column:is_erc721;default:false" json:"is_erc721"`
	IsERC1155 bool      `gorm:"column:is_erc1155;default:false" json:"is_erc1155"`
	QueriedAt time.Time `gorm:"column:queried_at;not null" json:"queried_at"`
}

// TableName overrides the default GORM table name.
func (TokenMetadata) TableName() string {
	return "token_metadata"
}
