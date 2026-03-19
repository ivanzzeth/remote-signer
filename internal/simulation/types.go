// Package simulation provides transaction simulation using anvil forks.
package simulation

import (
	"math/big"
)

// SimulationRequest represents a single transaction to simulate.
type SimulationRequest struct {
	ChainID string `json:"chain_id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Value   string `json:"value"` // hex
	Data    string `json:"data"`  // hex calldata
	Gas     string `json:"gas"`   // hex, optional
}

// TxParams represents a single transaction in a batch.
type TxParams struct {
	To    string `json:"to"`
	Value string `json:"value"` // hex
	Data  string `json:"data"`  // hex calldata
	Gas   string `json:"gas"`   // hex, optional
}

// BatchSimulationRequest represents multiple transactions to simulate in sequence.
type BatchSimulationRequest struct {
	ChainID      string     `json:"chain_id"`
	From         string     `json:"from"`
	Transactions []TxParams `json:"transactions"`
}

// SimulationResult is the result of simulating a single transaction.
type SimulationResult struct {
	Success        bool            `json:"success"`
	GasUsed        uint64          `json:"gas_used"`
	BalanceChanges []BalanceChange `json:"balance_changes"`
	Events         []SimEvent      `json:"events"`
	RawLogs        []txLog         `json:"-"` // raw logs for deep event analysis (not serialized to API)
	HasApproval    bool            `json:"has_approval"`
	RevertReason   string          `json:"revert_reason,omitempty"`
}

// BatchSimulationResult is the result of simulating a batch of transactions.
type BatchSimulationResult struct {
	Results           []SimulationResult `json:"results"`
	NetBalanceChanges []BalanceChange    `json:"net_balance_changes"`
}

// BalanceChange represents a token balance change from simulation.
type BalanceChange struct {
	Token     string   `json:"token"`               // token contract address, or "native" for ETH
	Standard  string   `json:"standard"`             // "erc20", "erc721", "erc1155", "native", "weth"
	Amount    *big.Int `json:"amount"`               // positive = inflow, negative = outflow
	Direction string   `json:"direction"`            // "inflow" or "outflow"
	TokenID   *big.Int `json:"token_id,omitempty"`   // non-nil for ERC721/ERC1155
}

// ManagerStatus is the overall status of the AnvilForkManager.
type ManagerStatus struct {
	Enabled      bool                    `json:"enabled"`
	AnvilVersion string                  `json:"anvil_version"`
	Chains       map[string]*ChainStatus `json:"chains"`
}

// ChainStatus is the status of a single anvil fork instance.
type ChainStatus struct {
	Status       string `json:"status"`                  // "healthy" or "unhealthy"
	Port         int    `json:"port"`
	BlockNumber  string `json:"block_number,omitempty"`   // hex block number from eth_blockNumber
	RestartCount int    `json:"restart_count"`
	Dirty        bool   `json:"dirty"`
	Error        string `json:"error,omitempty"`
}

// SimEvent represents a parsed event from simulation.
type SimEvent struct {
	Address  string            `json:"address"`
	Event    string            `json:"event"`    // "Transfer", "Approval", "Deposit", etc.
	Standard string            `json:"standard"` // "erc20", "erc721", "erc1155", "weth"
	Args     map[string]string `json:"args"`
}
