package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/metrics"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// maxBatchSize is the maximum number of transactions in a single batch sign request.
const maxBatchSize = 20

// BatchSignHandler handles POST /api/v1/evm/sign/batch
type BatchSignHandler struct {
	signService    *service.SignService
	signerManager  evm.SignerManager
	accessService  *service.SignerAccessService
	simulationRule *evm.SimulationBudgetRule
	ruleEngine     rule.RuleEngine
	logger         *slog.Logger
	alertService   *middleware.SecurityAlertService
	signTimeout    time.Duration
}

// BatchSignHandlerConfig contains dependencies for the BatchSignHandler.
type BatchSignHandlerConfig struct {
	SignService    *service.SignService
	SignerManager  evm.SignerManager
	AccessService *service.SignerAccessService
	SimulationRule *evm.SimulationBudgetRule
	RuleEngine     rule.RuleEngine
	Logger         *slog.Logger
}

// NewBatchSignHandler creates a new batch sign handler.
func NewBatchSignHandler(cfg BatchSignHandlerConfig) (*BatchSignHandler, error) {
	if cfg.SignService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if cfg.AccessService == nil {
		return nil, fmt.Errorf("access service is required")
	}
	if cfg.RuleEngine == nil {
		return nil, fmt.Errorf("rule engine is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &BatchSignHandler{
		signService:    cfg.SignService,
		signerManager:  cfg.SignerManager,
		accessService:  cfg.AccessService,
		simulationRule: cfg.SimulationRule,
		ruleEngine:     cfg.RuleEngine,
		logger:         cfg.Logger,
	}, nil
}

// SetAlertService sets the security alert service.
func (h *BatchSignHandler) SetAlertService(alertService *middleware.SecurityAlertService) {
	h.alertService = alertService
}

// SetSignTimeout sets the context timeout for sign operations.
func (h *BatchSignHandler) SetSignTimeout(d time.Duration) {
	h.signTimeout = d
}

// BatchSignRequest is the request body for POST /api/v1/evm/sign/batch.
type BatchSignRequest struct {
	Requests []BatchSignItem `json:"requests"`
}

// BatchSignItem is a single sign request within a batch.
type BatchSignItem struct {
	ChainID       string          `json:"chain_id"`
	SignerAddress string          `json:"signer_address"`
	SignType      string          `json:"sign_type"`
	Transaction   json.RawMessage `json:"transaction"`
}

// BatchSignResponse is the response for POST /api/v1/evm/sign/batch.
type BatchSignResponse struct {
	Results           []BatchSignResultItem `json:"results"`
	NetBalanceChanges []BalanceChangeJSON   `json:"net_balance_changes,omitempty"`
}

// BatchSignResultItem is a per-tx result in the batch response.
type BatchSignResultItem struct {
	Index      int               `json:"index"`
	RequestID  string            `json:"request_id,omitempty"`
	Signature  string            `json:"signature,omitempty"`
	SignedData string            `json:"signed_data,omitempty"`
	Simulation *SimulateResponse `json:"simulation,omitempty"`
}

// ServeHTTP handles POST /api/v1/evm/sign/batch.
func (h *BatchSignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse request
	var req BatchSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode batch sign request", "error", err)
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate batch
	if len(req.Requests) == 0 {
		h.writeError(w, "requests array is required and must not be empty", http.StatusBadRequest)
		return
	}
	if len(req.Requests) > maxBatchSize {
		h.writeError(w, fmt.Sprintf("batch size %d exceeds maximum %d", len(req.Requests), maxBatchSize), http.StatusBadRequest)
		return
	}

	// Validate all items and ensure they share the same chain_id and signer_address
	firstChainID := req.Requests[0].ChainID
	firstSigner := req.Requests[0].SignerAddress

	for i, item := range req.Requests {
		if item.ChainID == "" {
			h.writeError(w, fmt.Sprintf("requests[%d].chain_id is required", i), http.StatusBadRequest)
			return
		}
		if _, err := strconv.ParseUint(item.ChainID, 10, 64); err != nil {
			h.writeError(w, fmt.Sprintf("requests[%d].chain_id must be a positive decimal integer", i), http.StatusBadRequest)
			return
		}
		if item.SignerAddress == "" {
			h.writeError(w, fmt.Sprintf("requests[%d].signer_address is required", i), http.StatusBadRequest)
			return
		}
		if !validate.IsValidEthereumAddress(item.SignerAddress) {
			h.writeError(w, fmt.Sprintf("requests[%d].signer_address is invalid", i), http.StatusBadRequest)
			return
		}
		if item.SignType == "" {
			h.writeError(w, fmt.Sprintf("requests[%d].sign_type is required", i), http.StatusBadRequest)
			return
		}
		if item.SignType != "transaction" {
			h.writeError(w, fmt.Sprintf("requests[%d].sign_type must be 'transaction' for batch sign", i), http.StatusBadRequest)
			return
		}
		if len(item.Transaction) == 0 {
			h.writeError(w, fmt.Sprintf("requests[%d].transaction is required", i), http.StatusBadRequest)
			return
		}
		if item.ChainID != firstChainID {
			h.writeError(w, "all requests must have the same chain_id", http.StatusBadRequest)
			return
		}
		if item.SignerAddress != firstSigner {
			h.writeError(w, "all requests must have the same signer_address", http.StatusBadRequest)
			return
		}
	}

	// Check signer access
	allowed, err := h.accessService.CheckAccess(r.Context(), apiKey.ID, firstSigner)
	if err != nil {
		h.logger.Error("signer access check failed", "api_key_id", apiKey.ID, "signer_address", firstSigner, "error", err)
		h.writeError(w, "failed to check signer access", http.StatusInternalServerError)
		return
	}
	if !allowed {
		h.logger.Warn("signer permission denied for batch sign", "api_key_id", apiKey.ID, "signer_address", firstSigner)
		if h.alertService != nil {
			clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
			h.alertService.Alert(middleware.AlertSignerDenied, apiKey.ID,
				fmt.Sprintf("[Remote Signer] BATCH SIGNER ACCESS DENIED\n\nAPI Key: %s (%s)\nIP: %s\nSigner: %s\nBatch Size: %d\nTime: %s",
					apiKey.ID, apiKey.Name, clientIP, firstSigner, len(req.Requests),
					time.Now().UTC().Format(time.RFC3339)))
		}
		h.writeError(w, "not authorized for this signer", http.StatusForbidden)
		return
	}

	// Set up timeout
	signTimeout := h.signTimeout
	if signTimeout == 0 {
		signTimeout = 30 * time.Second
	}
	signCtx, signCancel := context.WithTimeout(r.Context(), signTimeout)
	defer signCancel()

	start := time.Now()
	clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)

	// Build payloads and parse each tx
	payloads := make([]json.RawMessage, len(req.Requests))
	parsedPayloads := make([]*types.ParsedPayload, len(req.Requests))
	evmPayloads := make([]*evm.EVMSignPayload, len(req.Requests))

	for i, item := range req.Requests {
		// Wrap the transaction object in the expected payload format
		wrapped, wrapErr := json.Marshal(map[string]json.RawMessage{
			"transaction": item.Transaction,
		})
		if wrapErr != nil {
			h.writeError(w, fmt.Sprintf("failed to build payload for requests[%d]", i), http.StatusInternalServerError)
			return
		}
		payloads[i] = wrapped

		var evmPayload evm.EVMSignPayload
		if parseErr := json.Unmarshal(wrapped, &evmPayload); parseErr != nil {
			h.writeError(w, fmt.Sprintf("invalid transaction payload for requests[%d]", i), http.StatusBadRequest)
			return
		}
		evmPayloads[i] = &evmPayload

		parsed := &types.ParsedPayload{RawData: wrapped}
		if evmPayload.Transaction != nil {
			parsed.Recipient = evmPayload.Transaction.To
			parsed.Value = &evmPayload.Transaction.Value
			dataHex := strings.TrimPrefix(evmPayload.Transaction.Data, "0x")
			if len(dataHex) >= 8 {
				sig := "0x" + dataHex[:8]
				parsed.MethodSig = &sig
				parsed.Contract = evmPayload.Transaction.To
			}
			rawData, decErr := hex.DecodeString(strings.TrimPrefix(evmPayload.Transaction.Data, "0x"))
			if decErr == nil && len(rawData) > 0 {
				parsed.RawData = rawData
			}
		}
		parsedPayloads[i] = parsed
	}

	// Phase 1: Run user-defined rules on each tx (blocklist check first)
	allRulesMatched := true

	for i := range req.Requests {
		signReq := &types.SignRequest{
			APIKeyID:      apiKey.ID,
			ChainType:     types.ChainTypeEVM,
			ChainID:       req.Requests[i].ChainID,
			SignerAddress:  req.Requests[i].SignerAddress,
			SignType:      req.Requests[i].SignType,
			Payload:       payloads[i],
			ClientIP:      clientIP,
		}

		matchedRuleID, _, evalErr := h.ruleEngine.Evaluate(signCtx, signReq, parsedPayloads[i])
		if evalErr != nil {
			var blockedErr *rule.BlockedError
			if errors.As(evalErr, &blockedErr) {
				h.logger.Warn("batch tx blocked by rule",
					"index", i,
					"rule_id", blockedErr.RuleID,
					"reason", blockedErr.Reason,
				)
				metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeRejected, time.Since(start))
				h.writeError(w, fmt.Sprintf("batch rejected: tx %d blocked by rule %s: %s", i, blockedErr.RuleName, blockedErr.Reason), http.StatusForbidden)
				return
			}
			h.logger.Error("rule evaluation error for batch tx", "index", i, "error", evalErr)
		}

		if matchedRuleID == nil {
			allRulesMatched = false
		}
	}

	// Phase 2: If not all txs matched user rules, try simulation fallback
	var batchSimResult *simulation.BatchSimulationResult
	if !allRulesMatched {
		if h.simulationRule != nil && h.simulationRule.Available() {
			// Build TxParams for simulation
			txParams := make([]simulation.TxParams, len(req.Requests))
			for i, ep := range evmPayloads {
				if ep.Transaction == nil {
					h.writeError(w, fmt.Sprintf("missing transaction in requests[%d]", i), http.StatusBadRequest)
					return
				}
				to := ""
				if ep.Transaction.To != nil {
					to = *ep.Transaction.To
				}
				// Convert decimal value to hex for anvil RPC
			hexValue := decimalToHex(ep.Transaction.Value)
			txParams[i] = simulation.TxParams{
				To:    to,
				Value: hexValue,
				Data:  ep.Transaction.Data,
				Gas:   fmt.Sprintf("0x%x", ep.Transaction.Gas),
			}
			}

			outcome, simErr := h.simulationRule.EvaluateBatch(signCtx, firstChainID, firstSigner, txParams)
			if simErr != nil {
				h.logger.Error("batch simulation evaluation error", "error", simErr)
				h.writeError(w, "batch simulation failed", http.StatusInternalServerError)
				return
			}

			batchSimResult = outcome.Simulation

			switch outcome.Decision {
			case "allow":
				// Proceed to signing
			case "no_match":
				// Approval detected or simulator issue — batch sign does not support manual approval
				metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeRejected, time.Since(start))
				h.writeError(w, "no matching rule for batch and simulation could not auto-approve (approval detected or simulator unavailable)", http.StatusForbidden)
				return
			case "deny":
				metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeRejected, time.Since(start))
				h.writeError(w, "batch rejected by simulation budget check", http.StatusForbidden)
				return
			default:
				h.writeError(w, "unexpected simulation outcome", http.StatusInternalServerError)
				return
			}
		} else {
			// No simulation available and not all rules matched
			metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeRejected, time.Since(start))
			h.writeError(w, "no matching rule for one or more transactions in batch", http.StatusForbidden)
			return
		}
	}

	// Phase 3: Sign all transactions
	results := make([]BatchSignResultItem, len(req.Requests))
	for i, item := range req.Requests {
		signReq := &service.SignRequest{
			APIKeyID:      apiKey.ID,
			ChainType:     types.ChainTypeEVM,
			ChainID:       item.ChainID,
			SignerAddress:  item.SignerAddress,
			SignType:      item.SignType,
			Payload:       payloads[i],
			ClientIP:      clientIP,
		}

		resp, signErr := h.signService.Sign(signCtx, signReq)
		if signErr != nil {
			h.logger.Error("batch sign failed for tx", "index", i, "error", signErr)
			metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeError, time.Since(start))
			h.writeError(w, fmt.Sprintf("batch sign failed at tx %d: %s", i, signErr.Error()), http.StatusInternalServerError)
			return
		}

		result := BatchSignResultItem{
			Index:     i,
			RequestID: string(resp.RequestID),
		}
		if len(resp.Signature) > 0 {
			result.Signature = fmt.Sprintf("0x%x", resp.Signature)
		}
		if len(resp.SignedData) > 0 {
			result.SignedData = fmt.Sprintf("0x%x", resp.SignedData)
		}

		// Attach per-tx simulation result if available
		if batchSimResult != nil && i < len(batchSimResult.Results) {
			simResult := batchSimResult.Results[i]
			result.Simulation = &SimulateResponse{
				Success:        simResult.Success,
				GasUsed:        simResult.GasUsed,
				BalanceChanges: toBalanceChangeJSON(simResult.BalanceChanges),
				Events:         simResult.Events,
				HasApproval:    simResult.HasApproval,
				RevertReason:   simResult.RevertReason,
			}
		}

		results[i] = result
	}

	duration := time.Since(start)
	metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeOK, duration)

	resp := BatchSignResponse{
		Results: results,
	}
	if batchSimResult != nil {
		resp.NetBalanceChanges = toBalanceChangeJSON(batchSimResult.NetBalanceChanges)
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *BatchSignHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *BatchSignHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}

// decimalToHex converts a decimal string value to hex format for anvil RPC.
// Returns "0x0" for empty or zero values.
func decimalToHex(decimal string) string {
	if decimal == "" || decimal == "0" {
		return "0x0"
	}
	// Already hex
	if strings.HasPrefix(decimal, "0x") || strings.HasPrefix(decimal, "0X") {
		return decimal
	}
	val := new(big.Int)
	if _, ok := val.SetString(decimal, 10); !ok {
		return "0x0"
	}
	return "0x" + val.Text(16)
}
