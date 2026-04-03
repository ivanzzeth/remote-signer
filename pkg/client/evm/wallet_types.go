package evm

import "time"

// Wallet represents an explicit wallet container.
type Wallet struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	OwnerID     string    `json:"owner_id,omitempty"`
	MemberCount int       `json:"member_count,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// WalletMember represents a signer member in a wallet.
type WalletMember struct {
	WalletID      string    `json:"wallet_id"`
	SignerAddress string    `json:"signer_address"`
	WalletType    string    `json:"wallet_type,omitempty"`
	AddedAt       time.Time `json:"added_at"`
}

// CreateWalletRequest represents a request to create a wallet.
type CreateWalletRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ListWalletsFilter contains filter options for listing wallets.
type ListWalletsFilter struct {
	Offset int
	Limit  int
}

// ListWalletsResponse represents the response from listing wallets.
type ListWalletsResponse struct {
	Wallets []Wallet `json:"wallets"`
	Total   int      `json:"total"`
	HasMore bool     `json:"has_more"`
}

// AddWalletMemberRequest represents a request to add a signer member to a wallet.
type AddWalletMemberRequest struct {
	SignerAddress string `json:"signer_address"`
}

// ListWalletMembersResponse represents the response from listing wallet members.
type ListWalletMembersResponse struct {
	Members []WalletMember `json:"members"`
}
