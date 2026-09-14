package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// SimulateHandler handles transaction simulation requests.
type SimulateHandler struct {
	simulator simulation.Simulator
	logger    *slog.Logger
}

// NewSimulateHandler creates a new simulation handler.
func NewSimulateHandler(simulator simulation.Simulator, logger *slog.Logger) (*SimulateHandler, error) {
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
//
// ⚠️ The first three are required and the last three are not, which the JSON
// tags do NOT show — none of them carries omitempty, so the struct looks
// uniform while the handler is not. Each required one gets a combined
// "<field> is required and must be ..." 400.
type SimulateRequest struct {
	ChainID string `json:"chain_id" binding:"required"`
	From    string `json:"from" binding:"required"`
	// ⛔ Required here, unlike a real transaction: this endpoint cannot
	// simulate a contract deployment (empty `to`).
	To string `json:"to" binding:"required"`
	// Optional. Empty is passed through to the simulator as-is.
	Value string `json:"value"`
	// Optional, but checked as 0x-prefixed hex when non-empty.
	Data string `json:"data"`
	// Optional; empty lets the simulator choose a gas limit.
	Gas string `json:"gas"`
}

// SimulateResponse is the JSON response for POST /api/v1/evm/simulate.
type SimulateResponse struct {
	Success          bool                  `json:"success"`
	GasUsed          uint64                `json:"gas_used"`
	BalanceChanges   []BalanceChangeJSON   `json:"balance_changes"`
	Events           []simulation.SimEvent `json:"events"`
	HasApproval      bool                  `json:"has_approval"`
	RevertReason     string                `json:"revert_reason,omitempty"`
	RevertData       string                `json:"revert_data,omitempty"`
	RevertSelector   string                `json:"revert_selector,omitempty"`
	RevertSignature  string                `json:"revert_signature,omitempty"`
	RevertSource     string                `json:"revert_source,omitempty"`
	RevertConfidence string                `json:"revert_confidence,omitempty"`
	RevertCandidates []string              `json:"revert_candidates,omitempty"`
	RevertArgs       map[string]string     `json:"revert_args,omitempty"`
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
	ChainID string `json:"chain_id" binding:"required"`
	From    string `json:"from" binding:"required"`
	// Rejected when absent or empty (400), capped at 20.
	Transactions []TxParamsJSON `json:"transactions" binding:"required"`
}

// TxParamsJSON is a single transaction in a batch.
type TxParamsJSON struct {
	// Rejected when empty or not an EVM address: 400
	// "transactions[i].to must be a valid 0x-prefixed Ethereum address".
	To string `json:"to" binding:"required"`
	// Optional.
	Value string `json:"value"`
	// Optional, but checked as 0x-prefixed hex when non-empty.
	Data string `json:"data"`
	// Optional.
	Gas string `json:"gas"`
}

// BatchSimulateResponse is the JSON response for POST /api/v1/evm/simulate/batch.
type BatchSimulateResponse struct {
	Results           []SimulateResultJSON `json:"results"`
	NetBalanceChanges []BalanceChangeJSON  `json:"net_balance_changes"`
}

// SimulateResultJSON is a per-tx result in a batch response.
type SimulateResultJSON struct {
	Index            int                   `json:"index"`
	Success          bool                  `json:"success"`
	GasUsed          uint64                `json:"gas_used"`
	BalanceChanges   []BalanceChangeJSON   `json:"balance_changes"`
	Events           []simulation.SimEvent `json:"events"`
	HasApproval      bool                  `json:"has_approval"`
	RevertReason     string                `json:"revert_reason,omitempty"`
	RevertData       string                `json:"revert_data,omitempty"`
	RevertSelector   string                `json:"revert_selector,omitempty"`
	RevertSignature  string                `json:"revert_signature,omitempty"`
	RevertSource     string                `json:"revert_source,omitempty"`
	RevertConfidence string                `json:"revert_confidence,omitempty"`
	RevertCandidates []string              `json:"revert_candidates,omitempty"`
	RevertArgs       map[string]string     `json:"revert_args,omitempty"`
}

// ServeHTTP handles POST /api/v1/evm/simulate.
//
//	@Summary	Simulate one transaction
//	@Description	Dry-run against the configured simulation backend. Signs nothing, broadcasts nothing, and does not consult the rule engine.
//	@Description	⚠️ A reverting transaction is a SUCCESSFUL simulation: 200 with `success:false` and the revert fields filled in. 500 means the simulator itself could not run, not that the transaction failed.
//	@Description	⚠️ `has_approval` is the flag the batch-sign path uses to refuse auto-approval, so it is worth reading even when `success` is true.
//	@Tags	simulation
//	@Accept	json
//	@Produce	json
//	@Param	body	body	SimulateRequest	true	"transaction to simulate"
//	@Success	200	{object}	SimulateResponse	"simulated; read `success` for the transaction outcome"
//	@Failure	400	{object}	map[string]string
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{object}	map[string]string	"the simulator could not run"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/simulate [post]
func (h *SimulateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ⛔ No method check: the route is method-scoped (see setupRoutes) and Go's
	// ServeMux answers 405 for anything else before this runs.

	var req SimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	if req.ChainID == "" || !validate.IsValidChainID(req.ChainID) {
		respond.Error(w, "chain_id is required and must be a positive decimal integer", http.StatusBadRequest, h.logger)
		return
	}
	if req.From == "" || !validate.IsValidEthereumAddress(req.From) {
		respond.Error(w, "from is required and must be a valid 0x-prefixed Ethereum address", http.StatusBadRequest, h.logger)
		return
	}
	if req.To == "" || !validate.IsValidEthereumAddress(req.To) {
		respond.Error(w, "to is required and must be a valid 0x-prefixed Ethereum address", http.StatusBadRequest, h.logger)
		return
	}
	if req.Data != "" && !validate.IsValidHexData(req.Data) {
		respond.Error(w, "data must be valid 0x-prefixed hex calldata", http.StatusBadRequest, h.logger)
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
		respond.Error(w, "simulation failed: "+err.Error(), http.StatusInternalServerError, h.logger)
		return
	}

	resp := SimulateResponse{
		Success:          result.Success,
		GasUsed:          result.GasUsed,
		BalanceChanges:   toBalanceChangeJSON(result.BalanceChanges),
		Events:           result.Events,
		HasApproval:      result.HasApproval,
		RevertReason:     result.RevertReason,
		RevertData:       result.RevertData,
		RevertSelector:   result.RevertSelector,
		RevertSignature:  result.RevertSignature,
		RevertSource:     result.RevertSource,
		RevertConfidence: result.RevertConfidence,
		RevertCandidates: result.RevertCandidates,
		RevertArgs:       result.RevertArgs,
	}

	respond.JSON(w, resp, http.StatusOK, h.logger)
}

// maxBatchSimulateSize is the maximum number of transactions in a single batch simulate request.
// Consistent with maxBatchSize in sign_batch.go.
const maxBatchSimulateSize = 20

// ServeBatchHTTP handles POST /api/v1/evm/simulate/batch.
//
//	@Summary	Simulate a batch of transactions
//	@Description	Up to 20 transactions, applied in order from one `from` on one chain, so later transactions see earlier ones' effects. `net_balance_changes` is the aggregate.
//	@Description	⚠️ A reverting transaction is a SUCCESSFUL simulation: 200 with `success:false` and the revert fields filled in. 500 means the simulator itself could not run, not that the transaction failed. A batch where some transactions revert still returns 200 with per-index `success` flags.
//	@Tags	simulation
//	@Accept	json
//	@Produce	json
//	@Param	body	body	BatchSimulateRequest	true	"transactions to simulate"
//	@Success	200	{object}	BatchSimulateResponse
//	@Failure	400	{object}	map[string]string	"empty or oversized batch, or a malformed item"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{object}	map[string]string	"the simulator could not run"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/simulate/batch [post]
func (h *SimulateHandler) ServeBatchHTTP(w http.ResponseWriter, r *http.Request) {
	// ⛔ No method check: the route is method-scoped (see setupRoutes) and Go's
	// ServeMux answers 405 for anything else before this runs.

	var req BatchSimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	if req.ChainID == "" || !validate.IsValidChainID(req.ChainID) {
		respond.Error(w, "chain_id is required and must be a positive decimal integer", http.StatusBadRequest, h.logger)
		return
	}
	if req.From == "" || !validate.IsValidEthereumAddress(req.From) {
		respond.Error(w, "from is required and must be a valid 0x-prefixed Ethereum address", http.StatusBadRequest, h.logger)
		return
	}
	if len(req.Transactions) == 0 {
		respond.Error(w, "transactions is required and must not be empty", http.StatusBadRequest, h.logger)
		return
	}
	if len(req.Transactions) > maxBatchSimulateSize {
		respond.Error(w, fmt.Sprintf("batch size %d exceeds maximum %d", len(req.Transactions), maxBatchSimulateSize), http.StatusBadRequest, h.logger)
		return
	}

	txs := make([]simulation.TxParams, len(req.Transactions))
	for i, tx := range req.Transactions {
		if tx.To == "" || !validate.IsValidEthereumAddress(tx.To) {
			respond.Error(w, fmt.Sprintf("transactions[%d].to must be a valid 0x-prefixed Ethereum address", i), http.StatusBadRequest, h.logger)
			return
		}
		if tx.Data != "" && !validate.IsValidHexData(tx.Data) {
			respond.Error(w, fmt.Sprintf("transactions[%d].data must be valid 0x-prefixed hex calldata", i), http.StatusBadRequest, h.logger)
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
		respond.Error(w, "batch simulation failed: "+err.Error(), http.StatusInternalServerError, h.logger)
		return
	}

	results := make([]SimulateResultJSON, len(result.Results))
	for i, r := range result.Results {
		results[i] = SimulateResultJSON{
			Index:            i,
			Success:          r.Success,
			GasUsed:          r.GasUsed,
			BalanceChanges:   toBalanceChangeJSON(r.BalanceChanges),
			Events:           r.Events,
			HasApproval:      r.HasApproval,
			RevertReason:     r.RevertReason,
			RevertData:       r.RevertData,
			RevertSelector:   r.RevertSelector,
			RevertSignature:  r.RevertSignature,
			RevertSource:     r.RevertSource,
			RevertConfidence: r.RevertConfidence,
			RevertCandidates: r.RevertCandidates,
			RevertArgs:       r.RevertArgs,
		}
	}

	resp := BatchSimulateResponse{
		Results:           results,
		NetBalanceChanges: toBalanceChangeJSON(result.NetBalanceChanges),
	}

	respond.JSON(w, resp, http.StatusOK, h.logger)
}

// ServeStatusHTTP handles GET /api/v1/evm/simulate/status.
//
//	@Summary	Simulator status
//	@Description	⚠️ Always 200, even when simulation is off or every chain is unhealthy — the state is in `enabled` and in each entry of `chains`, never in the status code.
//	@Description	⚠️ `chains` is empty on the RPC backend; per-chain health is only populated by backends that own processes.
//	@Tags	simulation
//	@Produce	json
//	@Success	200	{object}	simulation.ManagerStatus
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/simulate/status [get]
func (h *SimulateHandler) ServeStatusHTTP(w http.ResponseWriter, r *http.Request) {
	// ⛔ No method check: the route is method-scoped (see setupRoutes) and Go's
	// ServeMux answers 405 for anything else before this runs.

	status := h.simulator.Status(r.Context())
	respond.JSON(w, status, http.StatusOK, h.logger)
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
