package evm

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// --- Mock simulator for accumulator tests ---

type accMockSimulator struct {
	simulateBatchFn func(ctx context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error)
	batchCallCount  atomic.Int32
}

func (m *accMockSimulator) Simulate(_ context.Context, req *simulation.SimulationRequest) (*simulation.SimulationResult, error) {
	return &simulation.SimulationResult{Success: true, GasUsed: 21000}, nil
}

func (m *accMockSimulator) SimulateBatch(_ context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
	m.batchCallCount.Add(1)
	if m.simulateBatchFn != nil {
		return m.simulateBatchFn(nil, req)
	}
	// Default: all succeed
	results := make([]simulation.SimulationResult, len(req.Transactions))
	for i := range results {
		results[i] = simulation.SimulationResult{Success: true, GasUsed: 21000}
	}
	return &simulation.BatchSimulationResult{Results: results}, nil
}

func (m *accMockSimulator) SyncIfDirty(_ context.Context, _ string) error   { return nil }
func (m *accMockSimulator) MarkDirty(_ string)                              {}
func (m *accMockSimulator) Status(_ context.Context) *simulation.ManagerStatus { return &simulation.ManagerStatus{} }
func (m *accMockSimulator) Close() error                                    { return nil }

// --- Helpers ---

func newAccTestRule(t *testing.T, sim simulation.Simulator, window time.Duration, maxSize int) *SimulationBudgetRule {
	t.Helper()
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, slog.Default())
	require.NoError(t, err)
	r.SetBatchConfig(window, maxSize)
	r.StartAccumulator()
	t.Cleanup(func() { r.StopAccumulator() })
	return r
}

func makeTestSignRequest(chainID, signer string) *types.SignRequest {
	return &types.SignRequest{
		ChainID:       chainID,
		SignerAddress: signer,
		SignType:      SignTypeTransaction,
	}
}

func makeTestParsedPayload(to string) *types.ParsedPayload {
	return &types.ParsedPayload{
		Recipient: &to,
	}
}

// --- Tests ---

func TestAccumulator_SingleRequest_TimerFires(t *testing.T) {
	sim := &accMockSimulator{}
	r := newAccTestRule(t, sim, 200*time.Millisecond, 20)

	req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
	parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")

	start := time.Now()
	outcome, err := r.EvaluateSingle(context.Background(), req, parsed)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, "allow", outcome.Decision)
	// Should wait roughly the batch window before returning
	assert.True(t, elapsed >= 150*time.Millisecond, "should wait for batch window, elapsed: %v", elapsed)
	assert.Equal(t, int32(1), sim.batchCallCount.Load())
}

func TestAccumulator_BatchFull_FiresEarly(t *testing.T) {
	sim := &accMockSimulator{}
	maxSize := 5
	r := newAccTestRule(t, sim, 10*time.Second, maxSize) // long window, but batch fills first

	var wg sync.WaitGroup
	outcomes := make([]*SimulationOutcome, maxSize)
	errors := make([]error, maxSize)

	for i := 0; i < maxSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
			parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")
			outcomes[idx], errors[idx] = r.EvaluateSingle(context.Background(), req, parsed)
		}(i)
	}

	wg.Wait()

	for i := 0; i < maxSize; i++ {
		assert.NoError(t, errors[i], "request %d", i)
		assert.Equal(t, "allow", outcomes[i].Decision, "request %d", i)
	}
	assert.Equal(t, int32(1), sim.batchCallCount.Load(), "should be a single batch call")
}

func TestAccumulator_DifferentChains_SeparateBatches(t *testing.T) {
	sim := &accMockSimulator{}
	r := newAccTestRule(t, sim, 200*time.Millisecond, 20)

	var wg sync.WaitGroup
	// Send 2 requests to chain 1, 1 request to chain 137
	for _, chainID := range []string{"1", "1", "137"} {
		wg.Add(1)
		go func(cid string) {
			defer wg.Done()
			req := makeTestSignRequest(cid, "0x1111111111111111111111111111111111111111")
			parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")
			outcome, err := r.EvaluateSingle(context.Background(), req, parsed)
			assert.NoError(t, err)
			assert.Equal(t, "allow", outcome.Decision)
		}(chainID)
	}

	wg.Wait()

	// Should have 2 batch calls (one per chain)
	assert.Equal(t, int32(2), sim.batchCallCount.Load())
}

func TestAccumulator_ContextCancellation(t *testing.T) {
	sim := &accMockSimulator{}
	r := newAccTestRule(t, sim, 10*time.Second, 20) // long window

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
	parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")

	_, err := r.EvaluateSingle(ctx, req, parsed)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestAccumulator_SimulationError_NoMatch(t *testing.T) {
	sim := &accMockSimulator{
		simulateBatchFn: func(_ context.Context, _ *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
			return nil, fmt.Errorf("RPC connection failed")
		},
	}
	r := newAccTestRule(t, sim, 200*time.Millisecond, 20)

	req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
	parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")

	outcome, err := r.EvaluateSingle(context.Background(), req, parsed)
	require.NoError(t, err)
	assert.Equal(t, "no_match", outcome.Decision)
}

func TestAccumulator_TxRevert_DenyAll(t *testing.T) {
	sim := &accMockSimulator{
		simulateBatchFn: func(_ context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
			results := make([]simulation.SimulationResult, len(req.Transactions))
			for i := range results {
				results[i] = simulation.SimulationResult{Success: true, GasUsed: 21000}
			}
			// Second tx reverts
			if len(results) > 1 {
				results[1] = simulation.SimulationResult{Success: false, RevertReason: "insufficient balance"}
			}
			return &simulation.BatchSimulationResult{Results: results}, nil
		},
	}
	maxSize := 3
	r := newAccTestRule(t, sim, 10*time.Second, maxSize)

	var wg sync.WaitGroup
	outcomes := make([]*SimulationOutcome, maxSize)

	for i := 0; i < maxSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
			parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")
			outcomes[idx], _ = r.EvaluateSingle(context.Background(), req, parsed)
		}(i)
	}

	wg.Wait()

	// All should be denied
	for i, outcome := range outcomes {
		assert.Equal(t, "deny", outcome.Decision, "request %d should be denied", i)
	}
}

func TestAccumulator_Disabled_FallsThrough(t *testing.T) {
	sim := &accMockSimulator{}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, slog.Default())
	require.NoError(t, err)
	// Don't call SetBatchConfig/StartAccumulator — accumulator is disabled

	assert.False(t, r.accumulatorActive())

	req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
	parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")

	// Should go through the synchronous single-tx path
	outcome, err := r.EvaluateSingle(context.Background(), req, parsed)
	require.NoError(t, err)
	assert.Equal(t, "allow", outcome.Decision)
	// Single simulate called, not SimulateBatch
	assert.Equal(t, int32(0), sim.batchCallCount.Load())
}

func TestAccumulator_BudgetExceeded_DenyAll(t *testing.T) {
	sim := &accMockSimulator{
		simulateBatchFn: func(_ context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
			results := make([]simulation.SimulationResult, len(req.Transactions))
			for i := range results {
				results[i] = simulation.SimulationResult{
					Success: true,
					GasUsed: 21000,
				}
			}
			// Return net balance changes with large outflow to trigger budget exceeded
			return &simulation.BatchSimulationResult{
				Results: results,
				NetBalanceChanges: []simulation.BalanceChange{
					{Token: "native", Standard: "native", Amount: big.NewInt(-1e18), Direction: "outflow"},
				},
			}, nil
		},
	}

	// Create a budget repo that always returns ErrBudgetExceeded on AtomicSpend
	budgetRepo := &accMockBudgetRepo{
		atomicSpendFn: func(_ context.Context, _ types.RuleID, _, _ string) error {
			return storage.ErrBudgetExceeded
		},
		getByRuleIDFn: func(_ context.Context, _ types.RuleID, _ string) (*types.RuleBudget, error) {
			return &types.RuleBudget{
				MaxTotal: "1000",
				MaxPerTx: "-1",
				Spent:    "999",
			}, nil
		},
	}

	r, err := NewSimulationBudgetRule(sim, budgetRepo, nil, nil, nil, nil, slog.Default())
	require.NoError(t, err)
	r.SetBatchConfig(200*time.Millisecond, 20)
	r.StartAccumulator()
	defer r.StopAccumulator()

	var wg sync.WaitGroup
	outcomes := make([]*SimulationOutcome, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
			parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")
			outcomes[idx], _ = r.EvaluateSingle(context.Background(), req, parsed)
		}(i)
	}
	wg.Wait()

	for i, outcome := range outcomes {
		assert.Equal(t, "deny", outcome.Decision, "request %d should be denied due to budget", i)
		assert.Contains(t, outcome.Reason, "budget exceeded", "request %d reason", i)
	}
}

func TestAccumulator_ApprovalDetected_NoMatchAll(t *testing.T) {
	sim := &accMockSimulator{
		simulateBatchFn: func(_ context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
			results := make([]simulation.SimulationResult, len(req.Transactions))
			for i := range results {
				results[i] = simulation.SimulationResult{
					Success: true,
					GasUsed: 21000,
					Events: []simulation.SimEvent{
						{
							Event:    "Approval",
							Address: "0x1111111111111111111111111111111111111111",
							Standard: "erc20",
							Args: map[string]string{
								"owner":   "0x1111111111111111111111111111111111111111",
								"spender": "0x3333333333333333333333333333333333333333",
								"value":   "1000000",
							},
						},
					},
				}
			}
			return &simulation.BatchSimulationResult{Results: results}, nil
		},
	}

	// Create a signer lister that reports the signer as managed
	signerLister := &accMockSignerLister{
		signers: map[string]bool{
			"0x1111111111111111111111111111111111111111": true,
		},
	}

	// Allowance querier that confirms this is a real (new) approval
	allowanceQuerier := &accMockAllowanceQuerier{
		allowance: big.NewInt(0), // zero allowance before → new approval
	}

	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, signerLister, allowanceQuerier, slog.Default())
	require.NoError(t, err)
	r.SetBatchConfig(200*time.Millisecond, 20)
	r.StartAccumulator()
	defer r.StopAccumulator()

	req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
	parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")
	outcome, err := r.EvaluateSingle(context.Background(), req, parsed)

	require.NoError(t, err)
	assert.Equal(t, "no_match", outcome.Decision, "should defer to manual approval when approval detected")
}

func TestAccumulator_EmptyBatch_Noop(t *testing.T) {
	sim := &accMockSimulator{}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, slog.Default())
	require.NoError(t, err)
	// Calling fireBatch with empty batch should not panic
	r.fireBatch(&pendingBatch{})
	assert.Equal(t, int32(0), sim.batchCallCount.Load())
}

func TestAccumulator_DifferentSigners_SeparateBatches(t *testing.T) {
	sim := &accMockSimulator{}
	r := newAccTestRule(t, sim, 200*time.Millisecond, 20)

	var wg sync.WaitGroup
	signers := []string{
		"0x1111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222",
	}
	for _, signer := range signers {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			req := makeTestSignRequest("1", s)
			parsed := makeTestParsedPayload("0x3333333333333333333333333333333333333333")
			outcome, err := r.EvaluateSingle(context.Background(), req, parsed)
			assert.NoError(t, err)
			assert.Equal(t, "allow", outcome.Decision)
		}(signer)
	}
	wg.Wait()

	// 2 different signers on same chain = 2 separate batches
	assert.Equal(t, int32(2), sim.batchCallCount.Load())
}

// --- Additional mocks for budget/approval tests ---

type accMockBudgetRepo struct {
	atomicSpendFn func(ctx context.Context, ruleID types.RuleID, unit, amount string) error
	getByRuleIDFn func(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error)
}

func (m *accMockBudgetRepo) Create(_ context.Context, _ *types.RuleBudget) error   { return nil }
func (m *accMockBudgetRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	if m.getByRuleIDFn != nil {
		return m.getByRuleIDFn(ctx, ruleID, unit)
	}
	return nil, types.ErrNotFound
}
func (m *accMockBudgetRepo) Delete(_ context.Context, _ string) error              { return nil }
func (m *accMockBudgetRepo) DeleteByRuleID(_ context.Context, _ types.RuleID) error { return nil }
func (m *accMockBudgetRepo) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit, amount string) error {
	if m.atomicSpendFn != nil {
		return m.atomicSpendFn(ctx, ruleID, unit, amount)
	}
	return nil
}
func (m *accMockBudgetRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error {
	return nil
}
func (m *accMockBudgetRepo) ListByRuleID(_ context.Context, _ types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *accMockBudgetRepo) ListByRuleIDs(_ context.Context, _ []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *accMockBudgetRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error {
	return nil
}
func (m *accMockBudgetRepo) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) {
	return 0, nil
}
func (m *accMockBudgetRepo) CreateOrGet(_ context.Context, b *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return b, true, nil
}

type accMockSignerLister struct {
	signers map[string]bool
}

func (m *accMockSignerLister) ListManagedAddresses(_ context.Context) (map[string]bool, error) {
	return m.signers, nil
}

type accMockAllowanceQuerier struct {
	allowance *big.Int
}

func (m *accMockAllowanceQuerier) QueryAllowance(_ context.Context, _, _, _, _ string) (*big.Int, error) {
	return m.allowance, nil
}

func TestAccumulator_GracefulShutdown(t *testing.T) {
	sim := &accMockSimulator{}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, slog.Default())
	require.NoError(t, err)
	r.SetBatchConfig(10*time.Second, 20)
	r.StartAccumulator()

	// Enqueue a request that will be in the pending batch
	go func() {
		req := makeTestSignRequest("1", "0x1111111111111111111111111111111111111111")
		parsed := makeTestParsedPayload("0x2222222222222222222222222222222222222222")
		outcome, err := r.EvaluateSingle(context.Background(), req, parsed)
		// Should get a result (fired during shutdown)
		assert.NoError(t, err)
		assert.NotNil(t, outcome)
	}()

	// Give time for enqueue
	time.Sleep(50 * time.Millisecond)

	// Stop should fire pending batch and return
	r.StopAccumulator()
	assert.Equal(t, int32(1), sim.batchCallCount.Load())
}
