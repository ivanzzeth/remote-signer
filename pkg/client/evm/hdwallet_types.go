package evm

// CreateHDWalletRequest represents the request to create or import an HD wallet.
type CreateHDWalletRequest struct {
	Action      string `json:"action"`
	Password    string `json:"password"`
	Mnemonic    string `json:"mnemonic,omitempty"`
	EntropyBits int    `json:"entropy_bits,omitempty"`
}

// HDWalletResponse represents an HD wallet in API responses.
type HDWalletResponse struct {
	PrimaryAddress string       `json:"primary_address"`
	BasePath       string       `json:"base_path"`
	DerivedCount   int          `json:"derived_count"`
	Derived        []SignerInfo `json:"derived,omitempty"`
}

// ListHDWalletsResponse represents the response from listing HD wallets.
type ListHDWalletsResponse struct {
	Wallets []HDWalletResponse `json:"wallets"`
}

// DeriveAddressRequest represents the request to derive address(es).
type DeriveAddressRequest struct {
	Index *uint32 `json:"index,omitempty"`
	Start *uint32 `json:"start,omitempty"`
	Count *uint32 `json:"count,omitempty"`
}

// DeriveAddressResponse represents the response from deriving addresses.
type DeriveAddressResponse struct {
	Derived []SignerInfo `json:"derived"`
}

// ListDerivedAddressesResponse represents the response from listing derived addresses.
type ListDerivedAddressesResponse struct {
	Derived []SignerInfo `json:"derived"`
}
