package types

import "context"

// ChainType identifies the blockchain type
type ChainType string

const (
	ChainTypeEVM    ChainType = "evm"
	ChainTypeSolana ChainType = "solana" // future
	ChainTypeCosmos ChainType = "cosmos" // future
)

// ChainAdapter is the core abstraction for chain-specific operations
type ChainAdapter interface {
	// Type returns the chain type this adapter handles
	Type() ChainType

	// ValidatePayload validates chain-specific payload
	ValidatePayload(ctx context.Context, signType string, payload []byte) error

	// Sign performs the actual signing operation
	// chainID is the chain-specific identifier (e.g., "1" for Ethereum mainnet, "137" for Polygon)
	Sign(ctx context.Context, signerAddress string, signType string, chainID string, payload []byte) (*SignResult, error)

	// ParsePayload parses payload for rule evaluation (e.g., extract recipient, value)
	ParsePayload(ctx context.Context, signType string, payload []byte) (*ParsedPayload, error)

	// ListSigners returns available signers for this chain
	ListSigners(ctx context.Context) ([]SignerInfo, error)

	// HasSigner checks if a signer exists
	HasSigner(ctx context.Context, address string) bool
}

// Ensure EVMAdapter implements ChainAdapter at compile time
// This is done in the evm package with: var _ types.ChainAdapter = (*EVMAdapter)(nil)

// SignResult contains the signing result
type SignResult struct {
	Signature  []byte `json:"signature"`
	SignedData []byte `json:"signed_data,omitempty"` // e.g., signed tx for transaction type
	SignerUsed string `json:"signer_used"`
}

// ParsedPayload contains parsed info for rule evaluation
type ParsedPayload struct {
	Recipient *string `json:"recipient,omitempty"`  // e.g., tx.To
	Value     *string `json:"value,omitempty"`      // e.g., tx.Value in wei
	MethodSig *string `json:"method_sig,omitempty"` // e.g., 4-byte selector
	Contract  *string `json:"contract,omitempty"`   // e.g., contract address
	RawData   []byte  `json:"raw_data,omitempty"`   // original data
}

// SignerInfo describes a signer
type SignerInfo struct {
	Address string `json:"address"`
	Type    string `json:"type"` // "private_key", "keystore"
	Enabled bool   `json:"enabled"`
}
