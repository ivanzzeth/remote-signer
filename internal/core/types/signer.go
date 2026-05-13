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

// CreateKeystoreParams contains parameters for creating a keystore signer.
// Exactly one creation mode is selected at a time:
//   - Both PrivateKeyHex and KeystoreJSON empty: provider generates a fresh
//     secp256k1 key.
//   - PrivateKeyHex set: import the raw hex key (with or without 0x).
//   - KeystoreJSON set: decrypt the supplied v3 keystore JSON with Password,
//     then re-encrypt under the daemon's keystore dir. Useful for promoting
//     a keystore created by `remote-signer keystore create` (or by another
//     tool) into a signer the daemon will sign with.
type CreateKeystoreParams struct {
	Password      string `json:"password"`
	PrivateKeyHex string `json:"private_key_hex,omitempty"`
	KeystoreJSON  string `json:"keystore_json,omitempty"`
}

// CreateHDWalletParams contains parameters for creating an HD wallet
type CreateHDWalletParams struct {
	Password    string `json:"password"`
	EntropyBits int    `json:"entropy_bits,omitempty"` // 128-256, default 256
}

// ImportHDWalletParams contains parameters for importing an HD wallet.
// Exactly one of Mnemonic / WalletJSON should be set:
//   - Mnemonic: BIP-39 phrase the daemon entropy-encodes and stores.
//   - WalletJSON: full HDWalletFile JSON exported by `keystore export` or
//     copied off another remote-signer instance. The daemon decrypts the
//     embedded mnemonic with Password, then re-imports it.
type ImportHDWalletParams struct {
	Mnemonic   string `json:"mnemonic,omitempty"`
	WalletJSON string `json:"wallet_json,omitempty"`
	Password   string `json:"password"`
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
