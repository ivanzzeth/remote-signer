package evm

import (
	"encoding/json"
	"time"
)

// Sign types supported by the remote-signer.
const (
	SignTypeHash        = "hash"
	SignTypeRawMessage  = "raw_message"
	SignTypeEIP191      = "eip191"
	SignTypePersonal    = "personal"
	SignTypeTypedData   = "typed_data"
	SignTypeTransaction = "transaction"
)

// Request status values.
const (
	StatusPending     = "pending"
	StatusAuthorizing = "authorizing"
	StatusSigning     = "signing"
	StatusCompleted   = "completed"
	StatusRejected    = "rejected"
	StatusFailed      = "failed"
)

// SignRequest represents a signing request to the remote-signer service.
type SignRequest struct {
	ChainID       string          `json:"chain_id"`
	SignerAddress string          `json:"signer_address"`
	SignType      string          `json:"sign_type"`
	Payload       json.RawMessage `json:"payload"`
}

// SignResponse represents the response from a signing request.
type SignResponse struct {
	RequestID   string `json:"request_id"`
	Status      string `json:"status"`
	Signature   string `json:"signature,omitempty"`
	SignedData  string `json:"signed_data,omitempty"`
	Message     string `json:"message,omitempty"`
	RuleMatched string `json:"rule_matched_id,omitempty"`
}

// RequestStatus represents the status of a sign request.
type RequestStatus struct {
	ID            string          `json:"id"`
	APIKeyID      string          `json:"api_key_id"`
	ChainType     string          `json:"chain_type"`
	ChainID       string          `json:"chain_id"`
	SignerAddress string          `json:"signer_address"`
	SignType      string          `json:"sign_type"`
	Status        string          `json:"status"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	Signature     string          `json:"signature,omitempty"`
	SignedData    string          `json:"signed_data,omitempty"`
	ErrorMessage  string          `json:"error_message,omitempty"`
	RuleMatchedID *string         `json:"rule_matched_id,omitempty"`
	ApprovedBy    *string         `json:"approved_by,omitempty"`
	ApprovedAt    *time.Time      `json:"approved_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	CompletedAt   *time.Time      `json:"completed_at,omitempty"`
}

// HashPayload represents the payload for hash signing.
type HashPayload struct {
	Hash string `json:"hash"`
}

// RawMessagePayload represents the payload for raw message signing.
type RawMessagePayload struct {
	RawMessage []byte `json:"raw_message"`
}

// MessagePayload represents the payload for EIP-191/personal signing.
type MessagePayload struct {
	Message string `json:"message"`
}

// TypedDataPayload represents the payload for EIP-712 typed data signing.
type TypedDataPayload struct {
	TypedData *TypedData `json:"typed_data"`
}

// TypedData represents EIP-712 typed data structure.
type TypedData struct {
	Types       map[string][]TypedDataField `json:"types"`
	PrimaryType string                      `json:"primaryType"`
	Domain      TypedDataDomain             `json:"domain"`
	Message     map[string]interface{}      `json:"message"`
}

// TypedDataField represents a field in EIP-712 types.
type TypedDataField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// TypedDataDomain represents the EIP-712 domain separator.
type TypedDataDomain struct {
	Name              string `json:"name,omitempty"`
	Version           string `json:"version,omitempty"`
	ChainId           string `json:"chainId,omitempty"`
	VerifyingContract string `json:"verifyingContract,omitempty"`
	Salt              string `json:"salt,omitempty"`
}

// TransactionPayload represents the payload for transaction signing.
type TransactionPayload struct {
	Transaction *Transaction `json:"transaction"`
}

// Transaction represents an Ethereum transaction for signing.
type Transaction struct {
	To        *string `json:"to,omitempty"`
	Value     string  `json:"value"`
	Data      string  `json:"data,omitempty"`
	Nonce     *uint64 `json:"nonce,omitempty"`
	Gas       uint64  `json:"gas"`
	GasPrice  string  `json:"gasPrice,omitempty"`
	GasTipCap string  `json:"gasTipCap,omitempty"`
	GasFeeCap string  `json:"gasFeeCap,omitempty"`
	TxType    string  `json:"txType"`
}
