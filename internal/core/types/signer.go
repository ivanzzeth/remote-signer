package types

// SignerType identifies the signer type
type SignerType string

const (
	SignerTypePrivateKey SignerType = "private_key"
	SignerTypeKeystore   SignerType = "keystore"
	// Future types:
	// SignerTypeAWSKms    SignerType = "aws_kms"
	// SignerTypeVault     SignerType = "vault"
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
	Keystore *CreateKeystoreParams  `json:"keystore,omitempty"` // Required when type=keystore
	// Future types:
	// AWSKms   *CreateAWSKmsParams   `json:"aws_kms,omitempty"`
}

// CreateKeystoreParams contains parameters for creating a keystore signer
type CreateKeystoreParams struct {
	Password string `json:"password"`
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
	case SignerTypePrivateKey:
		return ErrPrivateKeyCreationNotSupported
	case "":
		return ErrMissingSignerType
	default:
		return ErrUnsupportedSignerType
	}
	return nil
}
