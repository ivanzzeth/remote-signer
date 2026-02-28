package evm

// Signer represents a signer configuration.
type Signer struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

// SignerInfo represents a signer in API responses (used by HD wallets).
type SignerInfo struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

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
