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

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

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
	signService    service.SignServiceAPI
	signerManager  evm.SignerManager
	accessService  *service.SignerAccessService
	simulationRule *evm.SimulationBudgetRule
	ruleEngine     rule.RuleEngine
	logger         *slog.Logger
	alertService   *middleware.SecurityAlertService
	signTimeout    func() time.Duration
}

// BatchSignHandlerConfig contains dependencies for the BatchSignHandler.
type BatchSignHandlerConfig struct {
	SignService    service.SignServiceAPI
	SignerManager  evm.SignerManager
	AccessService  *service.SignerAccessService
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
func (h *BatchSignHandler) SetSignTimeout(d func() time.Duration) {
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
	// ⛔ No method check: the route is method-scoped (see setupRoutes) and Go's
	// ServeMux answers 405 before this runs.

	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	// Parse request
	var req BatchSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode batch sign request", "error", err)
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	// Validate batch
	if len(req.Requests) == 0 {
		respond.Error(w, "requests array is required and must not be empty", http.StatusBadRequest, h.logger)
		return
	}
	if len(req.Requests) > maxBatchSize {
		respond.Error(w, fmt.Sprintf("batch size %d exceeds maximum %d", len(req.Requests), maxBatchSize), http.StatusBadRequest, h.logger)
		return
	}

	// Validate all items and ensure they share the same chain_id and signer_address
	firstChainID := req.Requests[0].ChainID
	firstSigner := req.Requests[0].SignerAddress

	for i, item := range req.Requests {
		if item.ChainID == "" {
			respond.Error(w, fmt.Sprintf("requests[%d].chain_id is required", i), http.StatusBadRequest, h.logger)
			return
		}
		if _, err := strconv.ParseUint(item.ChainID, 10, 64); err != nil {
			respond.Error(w, fmt.Sprintf("requests[%d].chain_id must be a positive decimal integer", i), http.StatusBadRequest, h.logger)
			return
		}
		if item.SignerAddress == "" {
			respond.Error(w, fmt.Sprintf("requests[%d].signer_address is required", i), http.StatusBadRequest, h.logger)
			return
		}
		if !validate.IsValidEthereumAddress(item.SignerAddress) {
			respond.Error(w, fmt.Sprintf("requests[%d].signer_address is invalid", i), http.StatusBadRequest, h.logger)
			return
		}
		if item.SignType == "" {
			respond.Error(w, fmt.Sprintf("requests[%d].sign_type is required", i), http.StatusBadRequest, h.logger)
			return
		}
		if item.SignType != "transaction" {
			respond.Error(w, fmt.Sprintf("requests[%d].sign_type must be 'transaction' for batch sign", i), http.StatusBadRequest, h.logger)
			return
		}
		if len(item.Transaction) == 0 {
			respond.Error(w, fmt.Sprintf("requests[%d].transaction is required", i), http.StatusBadRequest, h.logger)
			return
		}
		if item.ChainID != firstChainID {
			respond.Error(w, "all requests must have the same chain_id", http.StatusBadRequest, h.logger)
			return
		}
		if item.SignerAddress != firstSigner {
			respond.Error(w, "all requests must have the same signer_address", http.StatusBadRequest, h.logger)
			return
		}
	}

	// Check signer access
	allowed, err := h.accessService.CheckAccess(r.Context(), apiKey.ID, firstSigner)
	if err != nil {
		h.logger.Error("signer access check failed", "api_key_id", apiKey.ID, "signer_address", firstSigner, "error", err)
		respond.Error(w, "failed to check signer access", http.StatusInternalServerError, h.logger)
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
		respond.Error(w, "not authorized for this signer", http.StatusForbidden, h.logger)
		return
	}

	// Set up timeout
	signTimeout := h.signTimeoutValue()
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
			respond.Error(w, fmt.Sprintf("failed to build payload for requests[%d]", i), http.StatusInternalServerError, h.logger)
			return
		}
		payloads[i] = wrapped

		var evmPayload evm.EVMSignPayload
		if parseErr := json.Unmarshal(wrapped, &evmPayload); parseErr != nil {
			respond.Error(w, fmt.Sprintf("invalid transaction payload for requests[%d]", i), http.StatusBadRequest, h.logger)
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
			SignerAddress: req.Requests[i].SignerAddress,
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
				// SECURITY NOTE (V3-5): Rule names are intentionally included in error responses
				// to help agents and clients understand which security policy blocked their request.
				// Rule names are generic (e.g., "Agent Safety") and do not expose specific configuration
				// details. Accepted risk per security audit v3.
				respond.Error(w, fmt.Sprintf("batch rejected: tx %d blocked by rule %s: %s", i, blockedErr.RuleName, blockedErr.Reason), http.StatusForbidden, h.logger)
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
					respond.Error(w, fmt.Sprintf("missing transaction in requests[%d]", i), http.StatusBadRequest, h.logger)
					return
				}
				to := ""
				if ep.Transaction.To != nil {
					to = *ep.Transaction.To
				}
				// Convert decimal value to hex for JSON-RPC
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
				respond.Error(w, "batch simulation failed", http.StatusInternalServerError, h.logger)
				return
			}

			batchSimResult = outcome.Simulation

			switch outcome.Decision {
			case "allow":
				// Proceed to signing
			case "no_match":
				// Approval detected or simulator issue — batch sign does not support manual approval
				metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeRejected, time.Since(start))
				respond.Error(w, "no matching rule for batch and simulation could not auto-approve (approval detected or simulator unavailable)", http.StatusForbidden, h.logger)
				return
			case "deny":
				metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeRejected, time.Since(start))
				respond.Error(w, "batch rejected by simulation budget check", http.StatusForbidden, h.logger)
				return
			default:
				respond.Error(w, "unexpected simulation outcome", http.StatusInternalServerError, h.logger)
				return
			}
		} else {
			// No simulation available and not all rules matched
			metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeRejected, time.Since(start))
			respond.Error(w, "no matching rule for one or more transactions in batch", http.StatusForbidden, h.logger)
			return
		}
	}

	// Phase 3: Sign all transactions
	results := make([]BatchSignResultItem, len(req.Requests))
	for i, item := range req.Requests {
		signReq := &service.SignRequest{
			APIKeyID:      apiKey.ID,
			APIKeyRole:    apiKey.Role,
			ChainType:     types.ChainTypeEVM,
			ChainID:       item.ChainID,
			SignerAddress: item.SignerAddress,
			SignType:      item.SignType,
			Payload:       payloads[i],
			ClientIP:      clientIP,
		}

		resp, signErr := h.signService.Sign(signCtx, signReq)
		if signErr != nil {
			errResult := categorizeSignError(signErr, item.SignerAddress)
			h.logger.Error("batch sign failed for tx", "index", i, "error", signErr)
			metrics.RecordSignRequestDuration(string(types.ChainTypeEVM), "transaction", metrics.SignOutcomeError, time.Since(start))
			respond.Error(w, fmt.Sprintf("batch sign failed at tx %d: %s", i, errResult.Message), errResult.StatusCode, h.logger)
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

	respond.JSON(w, resp, http.StatusOK, h.logger)
}

// decimalToHex converts a decimal string value to hex format for JSON-RPC.
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

// signTimeoutValue reads the setting at request time. See Router.liveDuration /
// liveBool: the snapshot behind it is reloaded from the database, so a value
// captured at construction freezes at boot. nil keeps the previous meaning of
// "unset" — the handler falls back to its own default.
func (h *BatchSignHandler) signTimeoutValue() time.Duration {
	if h.signTimeout == nil {
		return 0
	}
	return h.signTimeout()
}
