// Package simulation provides transaction simulation via eth_simulateV1 RPC.
package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/metrics"
)

// RPCSimulatorConfig holds configuration for the RPC-based simulator.
type RPCSimulatorConfig struct {
	RPCGatewayURL string        // base URL for RPC gateway (e.g. http://localhost:8545/evm)
	RPCGatewayKey string        // optional API key
	Timeout       time.Duration // per-simulation timeout
}

// rpcSimulator implements Simulator using eth_simulateV1 via RPC gateway.
type rpcSimulator struct {
	cfg    RPCSimulatorConfig
	client *http.Client
	logger *slog.Logger
}

// NewRPCSimulator creates a new RPC-based simulator.
func NewRPCSimulator(cfg RPCSimulatorConfig, logger *slog.Logger) (Simulator, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if cfg.RPCGatewayURL == "" {
		return nil, fmt.Errorf("rpc gateway URL is required for simulation")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}

	return &rpcSimulator{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("rpc simulator does not follow redirects (SSRF prevention)")
			},
		},
		logger: logger,
	}, nil
}

// rpcURL returns the RPC endpoint for a chain.
func (s *rpcSimulator) rpcURL(chainID string) string {
	return strings.TrimSuffix(s.cfg.RPCGatewayURL, "/") + "/" + chainID
}

// Simulate simulates a single transaction via eth_simulateV1.
func (s *rpcSimulator) Simulate(ctx context.Context, req *SimulationRequest) (*SimulationResult, error) {
	start := time.Now()

	calls := []ethSimCall{{
		From:  req.From,
		To:    req.To,
		Value: normalizeRPCQuantity(req.Value),
		Data:  req.Data,
	}}
	if gas := normalizeRPCGasOptional(req.Gas); gas != "" {
		calls[0].Gas = gas
	}

	resp, err := s.callSimulateV1(ctx, req.ChainID, calls)
	if err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, err
	}

	if len(resp) == 0 || len(resp[0].Calls) == 0 {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, fmt.Errorf("empty simulation response")
	}

	result := s.parseCallResult(ctx, resp[0].Calls[0], req.From, req.To, req.Value)

	status := metrics.SimStatusSuccess
	if !result.Success {
		status = metrics.SimStatusRevert
	}
	metrics.RecordSimulationRequest(req.ChainID, status, time.Since(start))

	return result, nil
}

// SimulateBatch simulates multiple transactions in sequence via eth_simulateV1.
func (s *rpcSimulator) SimulateBatch(ctx context.Context, req *BatchSimulationRequest) (*BatchSimulationResult, error) {
	start := time.Now()
	metrics.RecordSimulationBatchSize(len(req.Transactions))

	calls := make([]ethSimCall, len(req.Transactions))
	for i, tx := range req.Transactions {
		calls[i] = ethSimCall{
			From:  req.From,
			To:    tx.To,
			Value: normalizeRPCQuantity(tx.Value),
			Data:  tx.Data,
		}
		if gas := normalizeRPCGasOptional(tx.Gas); gas != "" {
			calls[i].Gas = gas
		}
	}

	resp, err := s.callSimulateV1(ctx, req.ChainID, calls)
	if err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, err
	}

	if len(resp) == 0 || len(resp[0].Calls) != len(req.Transactions) {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, fmt.Errorf("unexpected simulation response: expected %d calls, got %d",
			len(req.Transactions), len(resp[0].Calls))
	}

	result := &BatchSimulationResult{
		Results: make([]SimulationResult, len(req.Transactions)),
	}

	allChanges := make(map[balanceKey]*big.Int)
	for i, tx := range req.Transactions {
		r := s.parseCallResult(ctx, resp[0].Calls[i], req.From, tx.To, tx.Value)
		result.Results[i] = *r

		// Accumulate net balance changes
		for _, bc := range r.BalanceChanges {
			key := balanceKey{token: strings.ToLower(bc.Token)}
			if bc.TokenID != nil {
				key.tokenID = bc.TokenID.String()
			}
			if _, ok := allChanges[key]; !ok {
				allChanges[key] = new(big.Int)
			}
			allChanges[key].Add(allChanges[key], bc.Amount)
		}
	}

	// Build net balance changes
	for key, amount := range allChanges {
		if amount.Sign() == 0 {
			continue
		}
		standard := "erc20"
		if key.token == "native" {
			standard = "native"
		}
		direction := "inflow"
		if amount.Sign() < 0 {
			direction = "outflow"
		}
		bc := BalanceChange{
			Token:     key.token,
			Standard:  standard,
			Amount:    amount,
			Direction: direction,
		}
		if key.tokenID != "" {
			tid := new(big.Int)
			tid.SetString(key.tokenID, 10)
			bc.TokenID = tid
		}
		result.NetBalanceChanges = append(result.NetBalanceChanges, bc)
	}

	status := metrics.SimStatusSuccess
	for _, r := range result.Results {
		if !r.Success {
			status = metrics.SimStatusRevert
			break
		}
	}
	metrics.RecordSimulationRequest(req.ChainID, status, time.Since(start))

	return result, nil
}

// SyncIfDirty is a no-op for RPC simulator (no local state to sync).
func (s *rpcSimulator) SyncIfDirty(_ context.Context, _ string) error { return nil }

// MarkDirty is a no-op for RPC simulator.
func (s *rpcSimulator) MarkDirty(_ string) {}

// Status returns the simulator status.
func (s *rpcSimulator) Status(_ context.Context) *ManagerStatus {
	return &ManagerStatus{
		Enabled:       true,
		EngineVersion: "rpc (eth_simulateV1)",
		Chains:        map[string]*ChainStatus{},
	}
}

// Close is a no-op for RPC simulator.
func (s *rpcSimulator) Close() error { return nil }

// ── eth_simulateV1 RPC types ────────────────────────────────────────────────

type ethSimCall struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value,omitempty"`
	Data  string `json:"data,omitempty"`
	Gas   string `json:"gas,omitempty"`
}

type ethSimBlockStateCall struct {
	Calls []ethSimCall `json:"calls"`
}

type ethSimV1Params struct {
	BlockStateCalls []ethSimBlockStateCall `json:"blockStateCalls"`
}

type ethSimCallResult struct {
	Status     string          `json:"status"` // "0x1" success, "0x0" revert
	GasUsed    string          `json:"gasUsed"`
	ReturnData string          `json:"returnData"`
	Logs       []ethSimLog     `json:"logs"`
	Error      *ethSimError    `json:"error,omitempty"`
}

type ethSimLog struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

type ethSimError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

type ethSimBlockResult struct {
	Calls []ethSimCallResult `json:"calls"`
}

// ── RPC call ────────────────────────────────────────────────────────────────

func (s *rpcSimulator) callSimulateV1(ctx context.Context, chainID string, calls []ethSimCall) ([]ethSimBlockResult, error) {
	params := ethSimV1Params{
		BlockStateCalls: []ethSimBlockStateCall{
			{Calls: calls},
		},
	}

	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_simulateV1",
		"params":  []interface{}{params, "latest"},
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("marshal rpc request: %w", err)
	}

	url := s.rpcURL(chainID)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if s.cfg.RPCGatewayKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+s.cfg.RPCGatewayKey)
	}

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rpc request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit, consistent with rpc_provider.go
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rpc HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var rpcResp struct {
		Result []ethSimBlockResult `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// ── Result parsing ──────────────────────────────────────────────────────────

func (s *rpcSimulator) parseCallResult(ctx context.Context, call ethSimCallResult, from, to, value string) *SimulationResult {
	gasUsed := uint64(0)
	if call.GasUsed != "" {
		g := new(big.Int)
		g.SetString(strings.TrimPrefix(call.GasUsed, "0x"), 16)
		gasUsed = g.Uint64()
	}

	success := call.Status == "0x1"

	// Parse events from logs (builtin + registry-resolved).
	rawLogs := ethSimLogsToTxLogs(call.Logs)
	allEvents := ParseEventsWithRegistry(ctx, rawLogs, GlobalSignatureRegistry())
	policyEvents := verifiedEventsOnly(allEvents)
	balanceChanges := ComputeBalanceChanges(policyEvents, from, to, value)

	// Mark HasApproval if any approval event exists (unfiltered).
	// The simulation budget rule re-checks with managed signer filtering.
	hasApproval := DetectApproval(context.Background(), policyEvents, nil, "", nil)

	result := &SimulationResult{
		Success:        success,
		GasUsed:        gasUsed,
		BalanceChanges: balanceChanges,
		Events:         allEvents,
		RawLogs:        rawLogs,
		HasApproval:    hasApproval,
	}

	if !success {
		errData := ""
		if call.Error != nil {
			errData = call.Error.Data
		}
		if revertData := revertDataFromCall(call.ReturnData, errData); revertData != "" {
			rev := ResolveRevert(ctx, GlobalSignatureRegistry(), revertData)
			result.RevertData = rev.Data
			result.RevertReason = rev.Reason
			result.RevertSelector = rev.Selector
			result.RevertSignature = rev.Signature
			result.RevertSource = rev.Source
			result.RevertConfidence = rev.Confidence
			result.RevertCandidates = rev.Candidates
			result.RevertArgs = rev.DecodedArgs
		} else {
			result.RevertReason = "transaction reverted"
		}
	}

	return result
}

// ethSimLogsToTxLogs converts eth_simulateV1 logs to TxLog (reuses existing parser).
func ethSimLogsToTxLogs(logs []ethSimLog) []TxLog {
	out := make([]TxLog, len(logs))
	for i, l := range logs {
		out[i] = TxLog(l)
	}
	return out
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}
