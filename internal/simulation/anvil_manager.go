package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/metrics"
)

const (
	maxRestartRetries = 3
	healthCheckPause  = 500 * time.Millisecond
)

// AnvilForkManager manages one persistent anvil process per chain_id.
type AnvilForkManager interface {
	// Simulate simulates a single transaction on the fork.
	Simulate(ctx context.Context, req *SimulationRequest) (*SimulationResult, error)

	// SimulateBatch simulates multiple transactions in sequence on the fork.
	SimulateBatch(ctx context.Context, req *BatchSimulationRequest) (*BatchSimulationResult, error)

	// SyncIfDirty resets the fork if the chain was marked dirty.
	SyncIfDirty(ctx context.Context, chainID string) error

	// MarkDirty marks a chain for lazy sync (call after tx broadcast).
	MarkDirty(chainID string)

	// Status returns the status of all running anvil fork instances.
	Status(ctx context.Context) *ManagerStatus

	// Close shuts down all anvil processes.
	Close() error
}

// AnvilForkManagerConfig holds configuration for the manager.
type AnvilForkManagerConfig struct {
	AnvilPath      string
	RPCGatewayURL  string // base URL for RPC gateway (e.g. https://gateway/chain/evm)
	RPCGatewayKey  string // optional API key
	SyncInterval   time.Duration
	Timeout        time.Duration
	MaxChains      int
	PruneHistory   int    // anvil --prune-history: max states in memory (0 = minimal, -1 = disabled/keep all)
	CacheDir       string // directory for anvil fork RPC cache (persists across restarts)
}

// anvilInstance represents a running anvil process.
type anvilInstance struct {
	mu           sync.Mutex
	chainID      string
	cmd          *exec.Cmd
	rpcURL       string
	port         int
	dirty        bool
	restartCount int
}

type anvilForkManagerImpl struct {
	cfg       AnvilForkManagerConfig
	instances map[string]*anvilInstance
	mu        sync.RWMutex
	logger    *slog.Logger
	client    *http.Client
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewAnvilForkManager creates a new AnvilForkManager.
func NewAnvilForkManager(cfg AnvilForkManagerConfig, logger *slog.Logger) (AnvilForkManager, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if cfg.RPCGatewayURL == "" {
		return nil, fmt.Errorf("rpc gateway URL is required for simulation")
	}

	// Resolve anvil path
	anvilPath := cfg.AnvilPath
	if anvilPath == "" {
		anvilPath = "data/foundry/anvil"
	}
	// Check if the path exists as-is first, then try PATH lookup
	if _, err := os.Stat(anvilPath); err != nil {
		pathLookup, lookupErr := exec.LookPath("anvil")
		if lookupErr != nil {
			return nil, fmt.Errorf("anvil not found at %q and not in PATH: %w", anvilPath, lookupErr)
		}
		anvilPath = pathLookup
	}
	cfg.AnvilPath = anvilPath

	// Ensure cache directory exists for persistent fork RPC cache
	if cfg.CacheDir != "" {
		if mkErr := os.MkdirAll(cfg.CacheDir, 0750); mkErr != nil {
			return nil, fmt.Errorf("failed to create anvil cache dir %s: %w", cfg.CacheDir, mkErr)
		}
		logger.Info("anvil cache directory ready", "path", cfg.CacheDir)
	}

	// Verify anvil is executable
	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer verifyCancel()
	out, err := exec.CommandContext(verifyCtx, anvilPath, "--version").CombinedOutput() // #nosec G204 -- admin-configured path
	if err != nil {
		return nil, fmt.Errorf("anvil not executable at %s: %w (output: %s)", anvilPath, err, string(out))
	}
	logger.Info("anvil binary verified", "path", anvilPath, "version", string(bytes.TrimSpace(out)))

	// Use configured timeout for per-RPC HTTP calls (default 10s).
	// Forked chains may need remote state fetches during evm_mine, so the
	// hardcoded 5s is often too short for slow or distant RPC gateways.
	httpTimeout := cfg.Timeout
	if httpTimeout <= 0 {
		httpTimeout = 60 * time.Second
	}

	m := &anvilForkManagerImpl{
		cfg:       cfg,
		instances: make(map[string]*anvilInstance),
		logger:    logger,
		client: &http.Client{
			Timeout: httpTimeout,
		},
		stopCh: make(chan struct{}),
	}

	// Start periodic sync goroutine
	if cfg.SyncInterval > 0 {
		m.wg.Add(1)
		go m.periodicHealthCheck()
	}

	return m, nil
}

// rpcURL builds the full RPC endpoint URL for a given chain ID.
func (m *anvilForkManagerImpl) rpcURL(chainID string) string {
	url := m.cfg.RPCGatewayURL + "/" + chainID
	if m.cfg.RPCGatewayKey != "" {
		url += "/api_key/" + m.cfg.RPCGatewayKey
	}
	return url
}

// getOrStartInstance returns the anvil instance for a chain, starting it lazily if needed.
func (m *anvilForkManagerImpl) getOrStartInstance(ctx context.Context, chainID string) (*anvilInstance, error) {
	m.mu.RLock()
	inst, exists := m.instances[chainID]
	m.mu.RUnlock()

	if exists {
		// Health check
		if m.healthCheck(ctx, inst) {
			return inst, nil
		}
		// Instance unhealthy, restart
		m.logger.Warn("anvil instance unhealthy, restarting", "chain_id", chainID)
		if err := m.restartInstance(ctx, inst); err != nil {
			return nil, fmt.Errorf("failed to restart anvil for chain %s: %w", chainID, err)
		}
		return inst, nil
	}

	// Check max chains limit
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if inst, exists := m.instances[chainID]; exists {
		return inst, nil
	}

	if len(m.instances) >= m.cfg.MaxChains {
		return nil, fmt.Errorf("max concurrent anvil forks reached (%d), cannot start fork for chain %s", m.cfg.MaxChains, chainID)
	}

	inst, err := m.startInstance(ctx, chainID)
	if err != nil {
		return nil, err
	}
	m.instances[chainID] = inst
	return inst, nil
}

// startInstance starts a new anvil process for the given chain.
func (m *anvilForkManagerImpl) startInstance(ctx context.Context, chainID string) (*anvilInstance, error) {
	port, err := findFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find free port: %w", err)
	}

	forkURL := m.rpcURL(chainID)
	rpcURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	args := []string{
		"--fork-url", forkURL,
		"--port", strconv.Itoa(port),
		"--no-mining",
		"--silent",
	}
	// Limit memory usage: prune historical states
	if m.cfg.PruneHistory >= 0 {
		args = append(args, "--prune-history", strconv.Itoa(m.cfg.PruneHistory))
	}

	// Use background context: anvil is a persistent process that must outlive individual requests.
	// The request ctx is only used for waiting on readiness, not for the process lifecycle.
	cmd := exec.CommandContext(context.Background(), m.cfg.AnvilPath, args...) // #nosec G204 -- admin-configured
	cmd.Stdout = nil
	// Set FOUNDRY_HOME so anvil persists fork RPC cache to disk.
	// This survives anvil restarts — subsequent forks of the same chain skip remote RPC calls.
	if m.cfg.CacheDir != "" {
		absCache, _ := filepath.Abs(m.cfg.CacheDir)
		cmd.Env = append(os.Environ(), "FOUNDRY_HOME="+absCache)
	}

	// Capture stderr so we can see crash messages
	stderrPipe, pipeErr := cmd.StderrPipe()
	if pipeErr != nil {
		return nil, fmt.Errorf("failed to create stderr pipe for anvil: %w", pipeErr)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start anvil for chain %s: %w", chainID, err)
	}

	inst := &anvilInstance{
		chainID: chainID,
		cmd:     cmd,
		rpcURL:  rpcURL,
		port:    port,
	}

	// Background goroutine: wait for anvil to exit and log the reason.
	// This ensures we know immediately when anvil dies (not just at the next health check).
	go func() {
		// Read stderr in background
		stderrBytes, _ := io.ReadAll(stderrPipe)
		waitErr := cmd.Wait()
		exitCode := -1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		stderrStr := strings.TrimSpace(string(stderrBytes))
		m.logger.Error("anvil process exited unexpectedly",
			"chain_id", chainID,
			"exit_code", exitCode,
			"error", waitErr,
			"stderr", stderrStr,
		)
	}()

	// Wait for anvil to become ready
	if err := m.waitForReady(ctx, inst); err != nil {
		// Kill the process if it didn't become ready
		if killErr := cmd.Process.Kill(); killErr != nil {
			m.logger.Error("failed to kill unready anvil process", "chain_id", chainID, "error", killErr)
		}
		return nil, fmt.Errorf("anvil for chain %s failed to become ready: %w", chainID, err)
	}

	m.logger.Info("anvil fork started", "chain_id", chainID, "port", port, "fork_url", forkURL)
	return inst, nil
}

// waitForReady polls anvil until it responds to eth_blockNumber.
func (m *anvilForkManagerImpl) waitForReady(ctx context.Context, inst *anvilInstance) error {
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if m.healthCheck(ctx, inst) {
			return nil
		}
		time.Sleep(healthCheckPause)
	}
	return fmt.Errorf("anvil did not become ready within 120s")
}

// healthCheck performs eth_blockNumber on the anvil instance.
func (m *anvilForkManagerImpl) healthCheck(ctx context.Context, inst *anvilInstance) bool {
	_, err := m.doAnvilRPC(ctx, inst, "eth_blockNumber", nil)
	return err == nil
}

// restartInstance restarts a crashed or unhealthy anvil instance.
func (m *anvilForkManagerImpl) restartInstance(ctx context.Context, inst *anvilInstance) error {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.restartCount >= maxRestartRetries {
		return fmt.Errorf("anvil for chain %s exceeded max restart retries (%d)", inst.chainID, maxRestartRetries)
	}
	inst.restartCount++

	// Kill existing process
	if inst.cmd != nil && inst.cmd.Process != nil {
		if err := inst.cmd.Process.Kill(); err != nil {
			m.logger.Warn("failed to kill old anvil process", "chain_id", inst.chainID, "error", err)
		}
		// Wait to avoid zombies
		if _, err := inst.cmd.Process.Wait(); err != nil {
			m.logger.Debug("wait on killed anvil process", "chain_id", inst.chainID, "error", err)
		}
	}

	// Start new process on the same port
	forkURL := m.rpcURL(inst.chainID)
	args := []string{
		"--fork-url", forkURL,
		"--port", strconv.Itoa(inst.port),
		"--no-mining",
		"--silent",
	}

	// Use background context for restart too — must not be tied to any request context
	cmd := exec.CommandContext(context.Background(), m.cfg.AnvilPath, args...) // #nosec G204
	cmd.Stdout = nil
	// Capture stderr for crash diagnostics
	restartStderrPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to restart anvil for chain %s: %w", inst.chainID, err)
	}
	inst.cmd = cmd

	// Monitor restarted process
	go func() {
		stderrBytes, _ := io.ReadAll(restartStderrPipe)
		waitErr := cmd.Wait()
		exitCode := -1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		m.logger.Error("restarted anvil process exited",
			"chain_id", inst.chainID,
			"exit_code", exitCode,
			"error", waitErr,
			"stderr", strings.TrimSpace(string(stderrBytes)),
		)
	}()

	if err := m.waitForReady(ctx, inst); err != nil {
		if killErr := cmd.Process.Kill(); killErr != nil {
			m.logger.Error("failed to kill unready restarted anvil", "chain_id", inst.chainID, "error", killErr)
		}
		return fmt.Errorf("restarted anvil for chain %s failed to become ready: %w", inst.chainID, err)
	}

	metrics.RecordAnvilForkRestart(inst.chainID)
	m.logger.Info("anvil fork restarted", "chain_id", inst.chainID, "restart_count", inst.restartCount)
	return nil
}

// Simulate simulates a single transaction.
// Uses an independent context (not tied to HTTP request) so that client disconnects
// don't kill the anvil process mid-simulation.
func (m *anvilForkManagerImpl) Simulate(ctx context.Context, req *SimulationRequest) (*SimulationResult, error) {
	start := time.Now()
	// Independent context: simulation must complete even if the caller's context is canceled
	// (e.g., HTTP client timeout). Otherwise anvil RPC calls get interrupted mid-execution,
	// leaving the fork in a broken state.
	simCtx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	inst, err := m.getOrStartInstance(simCtx, req.ChainID)
	if err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, err
	}

	// Sync if dirty
	if err := m.syncIfDirtyInternal(simCtx, inst); err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	// Snapshot
	snapshotID, err := m.snapshot(simCtx, inst)
	if err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, fmt.Errorf("snapshot failed: %w", err)
	}

	// Execute and collect result
	result, err := m.simulateSingleTx(simCtx, inst, req.From, req.To, req.Value, req.Data, req.Gas)

	// Always revert
	if revertErr := m.revert(simCtx, inst, snapshotID); revertErr != nil {
		m.logger.Error("revert failed after simulation", "chain_id", req.ChainID, "error", revertErr)
	}

	if err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, err
	}

	status := metrics.SimStatusSuccess
	if !result.Success {
		status = metrics.SimStatusRevert
	}
	metrics.RecordSimulationRequest(req.ChainID, status, time.Since(start))

	return result, nil
}

// SimulateBatch simulates multiple transactions in sequence.
// SimulateBatch simulates multiple transactions in sequence.
// Uses an independent context (not tied to HTTP request) to prevent client disconnects
// from killing anvil mid-simulation.
func (m *anvilForkManagerImpl) SimulateBatch(ctx context.Context, req *BatchSimulationRequest) (*BatchSimulationResult, error) {
	start := time.Now()
	metrics.RecordSimulationBatchSize(len(req.Transactions))
	simCtx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	inst, err := m.getOrStartInstance(simCtx, req.ChainID)
	if err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, err
	}

	// Sync if dirty
	if err := m.syncIfDirtyInternal(simCtx, inst); err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	// Snapshot
	snapshotID, err := m.snapshot(simCtx, inst)
	if err != nil {
		metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
		return nil, fmt.Errorf("snapshot failed: %w", err)
	}

	results := make([]SimulationResult, 0, len(req.Transactions))
	var allEvents []SimEvent

	for _, tx := range req.Transactions {
		result, err := m.simulateSingleTx(simCtx, inst, req.From, tx.To, tx.Value, tx.Data, tx.Gas)
		if err != nil {
			// Revert before returning
			if revertErr := m.revert(simCtx, inst, snapshotID); revertErr != nil {
				m.logger.Error("revert failed after batch simulation error", "chain_id", req.ChainID, "error", revertErr)
			}
			metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusError, time.Since(start))
			return nil, fmt.Errorf("simulation failed for tx %d: %w", len(results), err)
		}
		results = append(results, *result)
		allEvents = append(allEvents, result.Events...)
	}

	// Revert
	if revertErr := m.revert(simCtx, inst, snapshotID); revertErr != nil {
		m.logger.Error("revert failed after batch simulation", "chain_id", req.ChainID, "error", revertErr)
	}

	// Compute net balance changes
	netChanges := ComputeNetBalanceChanges(results, req.From)

	metrics.RecordSimulationRequest(req.ChainID, metrics.SimStatusSuccess, time.Since(start))

	return &BatchSimulationResult{
		Results:           results,
		NetBalanceChanges: netChanges,
	}, nil
}

// simulateSingleTx executes a single tx on the fork and parses the result.
func (m *anvilForkManagerImpl) simulateSingleTx(ctx context.Context, inst *anvilInstance, from, to, value, data, gas string) (*SimulationResult, error) {
	// Build tx params
	txObj := map[string]string{
		"from": from,
		"to":   to,
	}
	if value != "" && value != "0x0" && value != "0x" {
		txObj["value"] = value
	}
	if data != "" {
		txObj["data"] = data
	}
	if gas != "" {
		txObj["gas"] = gas
	}

	// Impersonate sender so anvil accepts the tx without a private key
	if _, impErr := m.doAnvilRPC(ctx, inst, "anvil_impersonateAccount", []interface{}{from}); impErr != nil {
		return nil, fmt.Errorf("impersonate account failed: %w", impErr)
	}

	// eth_sendTransaction (local execution)
	txHashRaw, err := m.doAnvilRPC(ctx, inst, "eth_sendTransaction", []interface{}{txObj})
	if err != nil {
		// Check if it's a revert
		return &SimulationResult{
			Success:      false,
			RevertReason: err.Error(),
		}, nil
	}

	var txHash string
	if err := json.Unmarshal(txHashRaw, &txHash); err != nil {
		return nil, fmt.Errorf("failed to parse tx hash: %w", err)
	}

	// Mine the block to get the receipt
	if _, err := m.doAnvilRPC(ctx, inst, "evm_mine", nil); err != nil {
		return nil, fmt.Errorf("evm_mine failed: %w", err)
	}

	// eth_getTransactionReceipt
	receiptRaw, err := m.doAnvilRPC(ctx, inst, "eth_getTransactionReceipt", []interface{}{txHash})
	if err != nil {
		return nil, fmt.Errorf("failed to get receipt: %w", err)
	}

	var receipt txReceipt
	if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
		return nil, fmt.Errorf("failed to parse receipt: %w", err)
	}

	// Parse gas used
	gasUsed, err := strconv.ParseUint(trimHexPrefix(receipt.GasUsed), 16, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gas used %q: %w", receipt.GasUsed, err)
	}

	// Check success (status "0x1" = success)
	success := receipt.Status == "0x1"

	// Parse events
	events := ParseEvents(receipt.Logs)

	// Parse balance changes from events + native value
	balanceChanges := ComputeBalanceChanges(events, from, to, value)

	// Detect approvals
	hasApproval := DetectApproval(events, data, nil) // nil = check all (anvil context doesn't have signer list)

	revertReason := ""
	if !success {
		revertReason = "transaction reverted"
	}

	return &SimulationResult{
		Success:        success,
		GasUsed:        gasUsed,
		BalanceChanges: balanceChanges,
		Events:         events,
		HasApproval:    hasApproval,
		RevertReason:   revertReason,
	}, nil
}

// SyncIfDirty syncs the chain if marked dirty.
func (m *anvilForkManagerImpl) SyncIfDirty(ctx context.Context, chainID string) error {
	m.mu.RLock()
	inst, exists := m.instances[chainID]
	m.mu.RUnlock()

	if !exists {
		return nil // no instance to sync
	}

	return m.syncIfDirtyInternal(ctx, inst)
}

func (m *anvilForkManagerImpl) syncIfDirtyInternal(ctx context.Context, inst *anvilInstance) error {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if !inst.dirty {
		return nil
	}

	forkURL := m.rpcURL(inst.chainID)
	resetParams := map[string]interface{}{
		"forking": map[string]string{
			"jsonRpcUrl": forkURL,
		},
	}

	if _, err := m.doAnvilRPCLocked(ctx, inst, "anvil_reset", []interface{}{resetParams}); err != nil {
		return fmt.Errorf("anvil_reset failed for chain %s: %w", inst.chainID, err)
	}

	inst.dirty = false
	metrics.RecordAnvilForkSync(inst.chainID)
	m.logger.Debug("anvil fork synced (dirty flag cleared)", "chain_id", inst.chainID)
	return nil
}

// MarkDirty marks a chain for lazy sync.
func (m *anvilForkManagerImpl) MarkDirty(chainID string) {
	m.mu.RLock()
	inst, exists := m.instances[chainID]
	m.mu.RUnlock()

	if !exists {
		return
	}

	inst.mu.Lock()
	inst.dirty = true
	inst.mu.Unlock()
}

// Status returns the status of all running anvil fork instances.
func (m *anvilForkManagerImpl) Status(ctx context.Context) *ManagerStatus {
	m.mu.RLock()
	chains := make(map[string]*anvilInstance, len(m.instances))
	for chainID, inst := range m.instances {
		chains[chainID] = inst
	}
	anvilPath := m.cfg.AnvilPath
	m.mu.RUnlock()

	// Get anvil version
	verCtx, verCancel := context.WithTimeout(ctx, 5*time.Second)
	defer verCancel()
	verOut, verErr := exec.CommandContext(verCtx, anvilPath, "--version").CombinedOutput() // #nosec G204 -- admin-configured path
	anvilVersion := ""
	if verErr == nil {
		anvilVersion = string(bytes.TrimSpace(verOut))
	}

	status := &ManagerStatus{
		Enabled:      true,
		AnvilVersion: anvilVersion,
		Chains:       make(map[string]*ChainStatus, len(chains)),
	}

	for chainID, inst := range chains {
		cs := &ChainStatus{
			Port: inst.port,
		}

		inst.mu.Lock()
		cs.RestartCount = inst.restartCount
		cs.Dirty = inst.dirty
		inst.mu.Unlock()

		// Health check: get block number
		blockRaw, err := m.doAnvilRPC(ctx, inst, "eth_blockNumber", nil)
		if err != nil {
			cs.Status = "unhealthy"
			cs.Error = err.Error()
		} else {
			cs.Status = "healthy"
			var blockNum string
			if jsonErr := json.Unmarshal(blockRaw, &blockNum); jsonErr == nil {
				cs.BlockNumber = blockNum
			}
		}

		status.Chains[chainID] = cs
	}

	return status
}

// Close shuts down all anvil processes.
func (m *anvilForkManagerImpl) Close() error {
	close(m.stopCh)
	m.wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for chainID, inst := range m.instances {
		if inst.cmd != nil && inst.cmd.Process != nil {
			if err := inst.cmd.Process.Signal(os.Interrupt); err != nil {
				// Try kill if interrupt fails
				if killErr := inst.cmd.Process.Kill(); killErr != nil {
					m.logger.Error("failed to kill anvil process", "chain_id", chainID, "error", killErr)
					if firstErr == nil {
						firstErr = killErr
					}
				}
			}
			if _, err := inst.cmd.Process.Wait(); err != nil {
				m.logger.Debug("wait on anvil shutdown", "chain_id", chainID, "error", err)
			}
		}
	}
	m.instances = make(map[string]*anvilInstance)
	m.logger.Info("all anvil forks shut down")
	return firstErr
}

// periodicHealthCheck monitors anvil instances and restarts unhealthy ones.
// State sync is handled exclusively by dirty-flag lazy sync (syncIfDirtyInternal),
// triggered before each simulation when MarkDirty() was called after a broadcast.
// We do NOT use periodic anvil_reset because it clears the state cache and
// invalidates any in-flight snapshot/revert operations.
func (m *anvilForkManagerImpl) periodicHealthCheck() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.mu.RLock()
			chains := make([]string, 0, len(m.instances))
			for chainID := range m.instances {
				chains = append(chains, chainID)
			}
			m.mu.RUnlock()

			for _, chainID := range chains {
				m.mu.RLock()
				inst := m.instances[chainID]
				m.mu.RUnlock()

				if inst == nil {
					continue
				}

				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if !m.healthCheck(ctx, inst) {
					m.logger.Warn("anvil instance unhealthy, restarting", "chain_id", chainID)
					if err := m.restartInstance(ctx, inst); err != nil {
						m.logger.Error("failed to restart anvil", "chain_id", chainID, "error", err)
					}
				}
				cancel()
			}
		}
	}
}

// snapshot creates a snapshot on the anvil instance.
func (m *anvilForkManagerImpl) snapshot(ctx context.Context, inst *anvilInstance) (string, error) {
	raw, err := m.doAnvilRPC(ctx, inst, "evm_snapshot", nil)
	if err != nil {
		return "", err
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil {
		return "", fmt.Errorf("failed to parse snapshot ID: %w", err)
	}
	return id, nil
}

// revert reverts to a snapshot.
func (m *anvilForkManagerImpl) revert(ctx context.Context, inst *anvilInstance, snapshotID string) error {
	_, err := m.doAnvilRPC(ctx, inst, "evm_revert", []interface{}{snapshotID})
	return err
}

// JSON-RPC types for anvil communication
type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      int             `json:"id"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// txReceipt represents relevant fields from eth_getTransactionReceipt.
type txReceipt struct {
	Status  string      `json:"status"`
	GasUsed string      `json:"gasUsed"`
	Logs    []txLog     `json:"logs"`
}

// txLog represents a single log entry from a transaction receipt.
type txLog struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// doAnvilRPC performs a JSON-RPC call to the anvil instance (acquires instance lock).
func (m *anvilForkManagerImpl) doAnvilRPC(ctx context.Context, inst *anvilInstance, method string, params []interface{}) (json.RawMessage, error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return m.doAnvilRPCLocked(ctx, inst, method, params)
}

// doAnvilRPCLocked performs a JSON-RPC call to the anvil instance (caller must hold lock).
func (m *anvilForkManagerImpl) doAnvilRPCLocked(ctx context.Context, inst *anvilInstance, method string, params []interface{}) (json.RawMessage, error) {
	if params == nil {
		params = []interface{}{}
	}

	reqBody, err := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rpc request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, inst.rpcURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rpc request to anvil failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil, fmt.Errorf("read anvil response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anvil returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal anvil response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("anvil rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// findFreePort finds an available TCP port.
func findFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, fmt.Errorf("failed to close listener: %w", err)
	}
	return port, nil
}

// trimHexPrefix removes 0x prefix from hex string.
func trimHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
