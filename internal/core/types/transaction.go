// Package types — on-chain transaction tracking model.
//
// SignRequest captures everything the daemon does up to producing
// signed bytes. Once those bytes are broadcast through the wallet
// RPC proxy, the chain state (was it mined? reverted? dropped from
// mempool?) lives in a separate Transaction row keyed by tx hash —
// SignRequest carries only the FK so a query for "what happened to
// this sign request on-chain" is one join, and a future
// re-broadcast scenario can attach multiple txs to the same sign
// request without bloating the latter's columns.

package types

import "time"

// TransactionStatus enumerates the chain-side lifecycle of a tx
// after the daemon broadcasts it.
type TransactionStatus string

const (
	// Broadcasted: the upstream RPC accepted eth_sendRawTransaction.
	// In mempool but not yet included in a block.
	TxStatusBroadcasted TransactionStatus = "broadcasted"
	// Mined: included in a block. Use ReceiptStatus to tell success
	// from on-chain revert.
	TxStatusMined TransactionStatus = "mined"
	// Dropped: the tx hash is no longer in mempool AND no receipt
	// after the configured grace period. Common causes: under-priced
	// gas, replaced-by-fee with the same nonce, mempool eviction.
	TxStatusDropped TransactionStatus = "dropped"
	// Failed: the upstream RPC rejected the broadcast outright
	// (invalid signature, chain-id mismatch, malformed payload).
	// Distinguished from Dropped because the tx never entered any
	// mempool; the ErrorMessage column carries the upstream reason.
	TxStatusFailed TransactionStatus = "failed"
)

// Transaction is the daemon's view of an on-chain transaction.
// One row per attempted broadcast — re-submissions with a bumped
// gas price would land in additional rows linked to the same
// SignRequest (today the link is 1:1 via SignRequest.TransactionID;
// a future commit can relax that).
type Transaction struct {
	ID string `json:"id" gorm:"primaryKey;type:varchar(64)"`

	// SignRequestID is the originating sign request, if known. Empty
	// when the proxy can't match the broadcast to one we signed
	// (third-party caller hit the proxy with a pre-signed payload).
	SignRequestID string `json:"sign_request_id,omitempty" gorm:"index;type:varchar(64)"`

	ChainID string `json:"chain_id" gorm:"index;type:varchar(32)"`
	// TxHash is the keccak256 hash of the signed RLP — the canonical
	// identifier on chain. Indexed for poller lookups.
	TxHash string `json:"tx_hash" gorm:"uniqueIndex:idx_tx_hash_chain;type:varchar(80)"`

	// FromAddress is the recovered signer (denormalised so the UI
	// doesn't have to join sign_requests to know who broadcast).
	FromAddress string `json:"from_address" gorm:"index;type:varchar(128)"`

	Status TransactionStatus `json:"status" gorm:"index;type:varchar(16)"`

	// Mined details — nullable until the poller observes the receipt.
	BlockNumber    *uint64 `json:"block_number,omitempty"`
	BlockHash      string  `json:"block_hash,omitempty" gorm:"type:varchar(80)"`
	TxIndex        *uint64 `json:"tx_index,omitempty"`
	GasUsed        *uint64 `json:"gas_used,omitempty"`
	// ReceiptStatus: 0 = on-chain revert, 1 = success. Nil while not
	// yet mined; nil after dropped/failed.
	ReceiptStatus *uint8 `json:"receipt_status,omitempty"`

	// ErrorMessage carries the upstream RPC reason for Failed status
	// (Broadcast rejection: "nonce too low", "intrinsic gas too low",
	// "underpriced"). Empty for non-failed states.
	ErrorMessage string `json:"error_message,omitempty" gorm:"type:text"`

	// LastCheckedAt is updated every time the poller fetches a
	// receipt; lets us throttle per-tx polling without re-scanning
	// the whole pending set on every tick.
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`

	BroadcastedAt time.Time  `json:"broadcasted_at"`
	MinedAt       *time.Time `json:"mined_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// TableName specifies the GORM table name.
func (Transaction) TableName() string {
	return "transactions"
}

// TransactionFilter filters list queries.
type TransactionFilter struct {
	SignRequestID string             // exact match
	ChainID       string             // exact match
	FromAddress   string             // exact match
	Status        *TransactionStatus // nil = any
	// SignType filters via the linked sign_request row.
	SignType string
	// APIKeyRole filters via sign_request → api_keys join (admin-only).
	APIKeyRole APIKeyRole
	// APIKeyID scopes to transactions whose linked sign_request was
	// created by this key. Implemented as a subquery against
	// sign_requests in the Gorm repo. The handler uses it to enforce
	// per-caller visibility — admins may pass any value, non-admins
	// only their own.
	APIKeyID string
	Limit    int // default 100, cap 500
	Offset   int
}
