package types

// SignerType identifies the signer type
type SignerType string

const (
	SignerTypePrivateKey SignerType = "private_key"
	SignerTypeKeystore   SignerType = "keystore"
	SignerTypeHDWallet   SignerType = "hd_wallet"
)

// SignerFilter defines filter options for listing signers
type SignerFilter struct {
	Type   *SignerType // Filter by signer type (nil = all types)
	Offset int
	Limit  int
}

// SignerListResult contains paginated signer list result
type SignerListResult struct {
	Signers []SignerInfo
	Total   int
	HasMore bool
}

// CreateSignerRequest is the request to create a new signer
type CreateSignerRequest struct {
	Type     SignerType             `json:"type"`
	Keystore *CreateKeystoreParams  `json:"keystore,omitempty"`  // Required when type=keystore
	HDWallet *CreateHDWalletParams  `json:"hd_wallet,omitempty"` // Required when type=hd_wallet
}

// TypedParams returns the type-specific params for provider dispatch.
func (r *CreateSignerRequest) TypedParams() interface{} {
	switch r.Type {
	case SignerTypeKeystore:
		return r.Keystore
	case SignerTypeHDWallet:
		return r.HDWallet
	default:
		return nil
	}
}

// CreateKeystoreParams contains parameters for creating a keystore signer
type CreateKeystoreParams struct {
	Password string `json:"password"`
}

// CreateHDWalletParams contains parameters for creating an HD wallet
type CreateHDWalletParams struct {
	Password    string `json:"password"`
	EntropyBits int    `json:"entropy_bits,omitempty"` // 128-256, default 256
}

// ImportHDWalletParams contains parameters for importing an HD wallet from mnemonic
type ImportHDWalletParams struct {
	Mnemonic string `json:"mnemonic"`
	Password string `json:"password"`
}

// DeriveAddressRequest is the request to derive a single address
type DeriveAddressRequest struct {
	Index uint32 `json:"index"`
}

// DeriveAddressesRequest is the request to derive multiple addresses
type DeriveAddressesRequest struct {
	Start uint32 `json:"start"`
	Count uint32 `json:"count"`
}

// Validate validates the create signer request
func (r *CreateSignerRequest) Validate() error {
	switch r.Type {
	case SignerTypeKeystore:
		if r.Keystore == nil {
			return ErrMissingKeystoreParams
		}
		if r.Keystore.Password == "" {
			return ErrEmptyPassword
		}
	case SignerTypeHDWallet:
		if r.HDWallet == nil {
			return ErrMissingHDWalletParams
		}
		if r.HDWallet.Password == "" {
			return ErrEmptyPassword
		}
	case SignerTypePrivateKey:
		return ErrPrivateKeyCreationNotSupported
	case "":
		return ErrMissingSignerType
	default:
		return ErrUnsupportedSignerType
	}
	return nil
}
