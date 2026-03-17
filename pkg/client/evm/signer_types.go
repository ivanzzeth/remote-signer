package evm

import "time"

// Signer represents a signer configuration.
type Signer struct {
	Address    string     `json:"address"`
	Type       string     `json:"type"`
	Enabled    bool       `json:"enabled"`
	Locked     bool       `json:"locked"`
	UnlockedAt *time.Time `json:"unlocked_at,omitempty"`
	OwnerID    string     `json:"owner_id,omitempty"`
	Status     string     `json:"status,omitempty"` // ownership status: active, pending_approval
}

// SignerAccessEntry represents an access grant on a signer.
type SignerAccessEntry struct {
	APIKeyID  string    `json:"api_key_id"`
	GrantedBy string    `json:"granted_by"`
	CreatedAt time.Time `json:"created_at"`
}

// GrantAccessRequest represents a request to grant signer access.
type GrantAccessRequest struct {
	APIKeyID string `json:"api_key_id"`
}

// TransferOwnershipRequest represents a request to transfer signer ownership.
type TransferOwnershipRequest struct {
	NewOwnerID string `json:"new_owner_id"`
}

// SignerInfo represents a signer in API responses (used by HD wallets).
type SignerInfo struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	Locked  bool   `json:"locked"`
}

// UnlockSignerRequest represents a request to unlock a locked signer.
type UnlockSignerRequest struct {
	Password string `json:"password"`
}

// UnlockSignerResponse represents the response after unlocking a signer.
type UnlockSignerResponse = Signer

// LockSignerResponse represents the response after locking a signer.
type LockSignerResponse = Signer

// ListSignersResponse represents the response from listing signers.
type ListSignersResponse struct {
	Signers []Signer `json:"signers"`
	Total   int      `json:"total"`
	HasMore bool     `json:"has_more"`
}

// CreateSignerRequest represents a request to create a new signer.
type CreateSignerRequest struct {
	Type     string                `json:"type"`
	Keystore *CreateKeystoreParams `json:"keystore,omitempty"`
}

// CreateKeystoreParams contains parameters for creating a keystore signer.
type CreateKeystoreParams struct {
	Password string `json:"password"`
}

// ListSignersFilter contains filter options for listing signers.
type ListSignersFilter struct {
	Type   string
	Offset int
	Limit  int
}
