package evm

import "time"

// Collection represents a wallet collection.
type Collection struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CollectionMember represents a member (wallet) in a collection.
type CollectionMember struct {
	WalletID   string    `json:"wallet_id"`
	WalletType string    `json:"wallet_type,omitempty"`
	AddedAt    time.Time `json:"added_at"`
}

// CreateCollectionRequest represents a request to create a collection.
type CreateCollectionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ListCollectionsFilter contains filter options for listing collections.
type ListCollectionsFilter struct {
	Offset int
	Limit  int
}

// ListCollectionsResponse represents the response from listing collections.
type ListCollectionsResponse struct {
	Collections []Collection `json:"collections"`
	Total       int          `json:"total"`
	HasMore     bool         `json:"has_more"`
}

// AddCollectionMemberRequest represents a request to add a member to a collection.
type AddCollectionMemberRequest struct {
	WalletID string `json:"wallet_id"`
}

// ListCollectionMembersResponse represents the response from listing collection members.
type ListCollectionMembersResponse struct {
	Members []CollectionMember `json:"members"`
	Total   int                `json:"total"`
	HasMore bool               `json:"has_more"`
}
