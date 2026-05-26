package evm

import "time"

// TransactionRecord represents an on-chain transaction record.
type TransactionRecord struct {
	ID            string    `json:"id"`
	ChainID       string    `json:"chain_id"`
	Hash          string    `json:"hash,omitempty"`
	From          string    `json:"from"`
	To            string    `json:"to,omitempty"`
	Value         string    `json:"value"`
	Data          string    `json:"data,omitempty"`
	Nonce         uint64    `json:"nonce,omitempty"`
	Gas           uint64    `json:"gas,omitempty"`
	GasPrice      string    `json:"gas_price,omitempty"`
	Status        string    `json:"status"`
	SignerAddress string    `json:"signer_address,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// ListTransactionsResponse represents the response from listing transactions.
type ListTransactionsResponse struct {
	Transactions []TransactionRecord `json:"transactions"`
	Total        int                 `json:"total"`
	HasMore      bool                `json:"has_more"`
}

// ListTransactionsFilter contains filter options for listing transactions.
type ListTransactionsFilter struct {
	Status        string
	SignerAddress string
	ChainID       string
	Limit         int
	Offset        int
}
