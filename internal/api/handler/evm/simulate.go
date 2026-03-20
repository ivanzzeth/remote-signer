package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// SimulateHandler handles transaction simulation requests.
type SimulateHandler struct {
	simulator simulation.AnvilForkManager
	logger    *slog.Logger
}

// NewSimulateHandler creates a new simulation handler.
func NewSimulateHandler(simulator simulation.AnvilForkManager, logger *slog.Logger) (*SimulateHandler, error) {
	if simulator == nil {
		return nil, fmt.Errorf("simulator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SimulateHandler{
		simulator: simulator,
		logger:    logger,
	}, nil
}

// SimulateRequest is the JSON request body for POST /api/v1/evm/simulate.
type SimulateRequest struct {
	ChainID string `json:"chain_id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Value   string `json:"value"`
	Data    string `json:"data"`
	Gas     string `json:"gas"`
}

// SimulateResponse is the JSON response for POST /api/v1/evm/simulate.
type SimulateResponse struct {
	Success        bool                      `json:"success"`
	GasUsed        uint64                    `json:"gas_used"`
	BalanceChanges []BalanceChangeJSON       `json:"balance_changes"`
	Events         []simulation.SimEvent     `json:"events"`
	HasApproval    bool                      `json:"has_approval"`
	RevertReason   string                    `json:"revert_reason,omitempty"`
}

// BalanceChangeJSON is the JSON-friendly representation of a BalanceChange.
type BalanceChangeJSON struct {
	Token     string `json:"token"`
	Standard  string `json:"standard"`
	Amount    string `json:"amount"`
	Direction string `json:"direction"`
	TokenID   string `json:"token_id,omitempty"`
}

// BatchSimulateRequest is the JSON request body for POST /api/v1/evm/simulate/batch.
type BatchSimulateRequest struct {
	ChainID      string              `json:"chain_id"`
	From         string              `json:"from"`
	Transactions []TxParamsJSON      `json:"transactions"`
}

// TxParamsJSON is a single transaction in a batch.
type TxParamsJSON struct {
	To    string `json:"to"`
	Value string `json:"value"`
	Data  string `json:"data"`
	Gas   string `json:"gas"`
}

// BatchSimulateResponse is the JSON response for POST /api/v1/evm/simulate/batch.
type BatchSimulateResponse struct {
	Results           []SimulateResultJSON `json:"results"`
	NetBalanceChanges []BalanceChangeJSON  `json:"net_balance_changes"`
}

// SimulateResultJSON is a per-tx result in a batch response.
type SimulateResultJSON struct {
	Index          int                  `json:"index"`
	Success        bool                 `json:"success"`
	GasUsed        uint64               `json:"gas_used"`
	BalanceChanges []BalanceChangeJSON  `json:"balance_changes"`
	Events         []simulation.SimEvent `json:"events"`
	HasApproval    bool                 `json:"has_approval"`
	RevertReason   string               `json:"revert_reason,omitempty"`
}

// ServeHTTP handles POST /api/v1/evm/simulate.
func (h *SimulateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChainID == "" || !validate.IsValidChainID(req.ChainID) {
		h.writeError(w, "chain_id is required and must be a positive decimal integer", http.StatusBadRequest)
		return
	}
	if req.From == "" || !validate.IsValidEthereumAddress(req.From) {
		h.writeError(w, "from is required and must be a valid 0x-prefixed Ethereum address", http.StatusBadRequest)
		return
	}
	if req.To == "" || !validate.IsValidEthereumAddress(req.To) {
		h.writeError(w, "to is required and must be a valid 0x-prefixed Ethereum address", http.StatusBadRequest)
		return
	}
	if req.Data != "" && !validate.IsValidHexData(req.Data) {
		h.writeError(w, "data must be valid 0x-prefixed hex calldata", http.StatusBadRequest)
		return
	}

	simReq := &simulation.SimulationRequest{
		ChainID: req.ChainID,
		From:    req.From,
		To:      req.To,
		Value:   req.Value,
		Data:    req.Data,
		Gas:     req.Gas,
	}

	result, err := h.simulator.Simulate(r.Context(), simReq)
	if err != nil {
		h.logger.Error("simulation failed", "chain_id", req.ChainID, "from", req.From, "error", err)
		h.writeError(w, "simulation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := SimulateResponse{
		Success:        result.Success,
		GasUsed:        result.GasUsed,
		BalanceChanges: toBalanceChangeJSON(result.BalanceChanges),
		Events:         result.Events,
		HasApproval:    result.HasApproval,
		RevertReason:   result.RevertReason,
	}

	h.writeJSON(w, resp, http.StatusOK)
}

// maxBatchSimulateSize is the maximum number of transactions in a single batch simulate request.
// Consistent with maxBatchSize in sign_batch.go.
const maxBatchSimulateSize = 20

// ServeBatchHTTP handles POST /api/v1/evm/simulate/batch.
func (h *SimulateHandler) ServeBatchHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BatchSimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChainID == "" || !validate.IsValidChainID(req.ChainID) {
		h.writeError(w, "chain_id is required and must be a positive decimal integer", http.StatusBadRequest)
		return
	}
	if req.From == "" || !validate.IsValidEthereumAddress(req.From) {
		h.writeError(w, "from is required and must be a valid 0x-prefixed Ethereum address", http.StatusBadRequest)
		return
	}
	if len(req.Transactions) == 0 {
		h.writeError(w, "transactions is required and must not be empty", http.StatusBadRequest)
		return
	}
	if len(req.Transactions) > maxBatchSimulateSize {
		h.writeError(w, fmt.Sprintf("batch size %d exceeds maximum %d", len(req.Transactions), maxBatchSimulateSize), http.StatusBadRequest)
		return
	}

	txs := make([]simulation.TxParams, len(req.Transactions))
	for i, tx := range req.Transactions {
		if tx.To == "" || !validate.IsValidEthereumAddress(tx.To) {
			h.writeError(w, fmt.Sprintf("transactions[%d].to must be a valid 0x-prefixed Ethereum address", i), http.StatusBadRequest)
			return
		}
		if tx.Data != "" && !validate.IsValidHexData(tx.Data) {
			h.writeError(w, fmt.Sprintf("transactions[%d].data must be valid 0x-prefixed hex calldata", i), http.StatusBadRequest)
			return
		}
		txs[i] = simulation.TxParams{
			To:    tx.To,
			Value: tx.Value,
			Data:  tx.Data,
			Gas:   tx.Gas,
		}
	}

	batchReq := &simulation.BatchSimulationRequest{
		ChainID:      req.ChainID,
		From:         req.From,
		Transactions: txs,
	}

	result, err := h.simulator.SimulateBatch(r.Context(), batchReq)
	if err != nil {
		h.logger.Error("batch simulation failed", "chain_id", req.ChainID, "from", req.From, "error", err)
		h.writeError(w, "batch simulation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	results := make([]SimulateResultJSON, len(result.Results))
	for i, r := range result.Results {
		results[i] = SimulateResultJSON{
			Index:          i,
			Success:        r.Success,
			GasUsed:        r.GasUsed,
			BalanceChanges: toBalanceChangeJSON(r.BalanceChanges),
			Events:         r.Events,
			HasApproval:    r.HasApproval,
			RevertReason:   r.RevertReason,
		}
	}

	resp := BatchSimulateResponse{
		Results:           results,
		NetBalanceChanges: toBalanceChangeJSON(result.NetBalanceChanges),
	}

	h.writeJSON(w, resp, http.StatusOK)
}

// ServeStatusHTTP handles GET /api/v1/evm/simulate/status.
func (h *SimulateHandler) ServeStatusHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := h.simulator.Status(r.Context())
	h.writeJSON(w, status, http.StatusOK)
}

// toBalanceChangeJSON converts simulation BalanceChange to JSON-friendly format.
func toBalanceChangeJSON(changes []simulation.BalanceChange) []BalanceChangeJSON {
	result := make([]BalanceChangeJSON, len(changes))
	for i, bc := range changes {
		result[i] = BalanceChangeJSON{
			Token:     bc.Token,
			Standard:  bc.Standard,
			Amount:    bigIntToString(bc.Amount),
			Direction: bc.Direction,
		}
		if bc.TokenID != nil {
			result[i].TokenID = bc.TokenID.String()
		}
	}
	return result
}

// bigIntToString safely converts a *big.Int to string.
func bigIntToString(n *big.Int) string {
	if n == nil {
		return "0"
	}
	return n.String()
}

func (h *SimulateHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *SimulateHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
