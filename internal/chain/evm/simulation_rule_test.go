package evm

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSimulator implements simulation.AnvilForkManager for testing.
type mockSimulator struct {
	simulateResult      *simulation.SimulationResult
	simulateErr         error
	simulateBatchResult *simulation.BatchSimulationResult
	simulateBatchErr    error
}

func (m *mockSimulator) Simulate(_ context.Context, _ *simulation.SimulationRequest) (*simulation.SimulationResult, error) {
	return m.simulateResult, m.simulateErr
}

func (m *mockSimulator) SimulateBatch(_ context.Context, _ *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
	return m.simulateBatchResult, m.simulateBatchErr
}

func (m *mockSimulator) SyncIfDirty(_ context.Context, _ string) error { return nil }
func (m *mockSimulator) MarkDirty(_ string)                            {}
func (m *mockSimulator) Status(_ context.Context) *simulation.ManagerStatus {
	return &simulation.ManagerStatus{Enabled: true}
}
func (m *mockSimulator) Close() error { return nil }

func simTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func TestSimulationBudgetRule_NotAvailable(t *testing.T) {
	r, err := NewSimulationBudgetRule(nil, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	assert.False(t, r.Available())

	outcome, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		SignType: SignTypeTransaction,
	}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.Equal(t, "no_match", outcome.Decision)
}

func TestSimulationBudgetRule_NonTransactionSignType(t *testing.T) {
	sim := &mockSimulator{}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	outcome, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		SignType: SignTypePersonal,
	}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.Equal(t, "no_match", outcome.Decision)
}

func TestSimulationBudgetRule_SimulationReverts(t *testing.T) {
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success:      false,
			RevertReason: "execution reverted",
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	to := "0x1234567890abcdef1234567890abcdef12345678"
	val := "0"
	outcome, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		SignType:      SignTypeTransaction,
	}, &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	})
	require.NoError(t, err)
	assert.Equal(t, "deny", outcome.Decision)
	assert.NotNil(t, outcome.Simulation)
}

func TestSimulationBudgetRule_ApprovalOnly_RequiresManualApproval(t *testing.T) {
	// Approve tx: simulation emits Approval event with non-zero value for our signer.
	// Budget passes (no outflow), but approval detected → manual approval required.
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success:     true,
			HasApproval: true,
			Events: []simulation.SimEvent{
				{Event: "Approval", Standard: "erc20", Args: map[string]string{
					"owner": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "spender": "0x5b38da6a701c568545dcfcb03fcb875f56beddc4", "value": "1000000",
				}},
			},
			BalanceChanges: []simulation.BalanceChange{},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	to := "0x1234567890abcdef1234567890abcdef12345678"
	val := "0"
	outcome, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		SignType:      SignTypeTransaction,
	}, &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	})
	require.NoError(t, err)
	// Approve: budget passes (no outflow) but HasApproval → no_match → manual approval
	assert.Equal(t, "no_match", outcome.Decision)
	assert.NotNil(t, outcome.Simulation)
}

func TestSimulationBudgetRule_SwapWithApproval_TracksBudget(t *testing.T) {
	// DEX swap: has Approval event with value=0 (transferFrom side effect) + actual outflow.
	// value=0 approval is NOT a real approval grant → should auto-allow, not manual approval.
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success:     true,
			HasApproval: true,
			Events: []simulation.SimEvent{
				{Event: "Approval", Standard: "erc20", Args: map[string]string{
					"owner": "0x764602fead618416e42b48c633d90869ff19759e", "spender": "0x3b86917369b83a6892f553609f3c2f439c184e31", "value": "0",
				}},
				{Event: "Transfer", Standard: "erc20"},
			},
			BalanceChanges: []simulation.BalanceChange{
				{Token: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", Standard: "erc20", Amount: big.NewInt(-1000000), Direction: "outflow"},
				{Token: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", Standard: "erc20", Amount: big.NewInt(999989), Direction: "inflow"},
			},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	to := "0x057cfd839aa88994d1a8a8c6d336cf21550f05ef"
	val := "0"
	outcome, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		ChainID:       "137",
		SignerAddress: "0x764602FeaD618416E42b48c633d90869fF19759E",
		SignType:      SignTypeTransaction,
	}, &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	})
	require.NoError(t, err)
	// value=0 approval is skipped → no managed signer approval → auto-allow
	assert.Equal(t, "allow", outcome.Decision)
}

func TestSimulationBudgetRule_SwapNoApproval_Allow(t *testing.T) {
	// Simple swap without approval events → budget check → allow.
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success:     true,
			HasApproval: false,
			Events: []simulation.SimEvent{
				{Event: "Transfer", Standard: "erc20"},
			},
			BalanceChanges: []simulation.BalanceChange{
				{Token: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", Amount: big.NewInt(-1000000), Direction: "outflow"},
				{Token: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", Amount: big.NewInt(999989), Direction: "inflow"},
			},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	to := "0x057cfd839aa88994d1a8a8c6d336cf21550f05ef"
	val := "0"
	outcome, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		ChainID:       "137",
		SignerAddress: "0x764602FeaD618416E42b48c633d90869fF19759E",
		SignType:      SignTypeTransaction,
	}, &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	})
	require.NoError(t, err)
	// No approval event → budget passes → allow (auto-sign)
	assert.Equal(t, "allow", outcome.Decision)
}

func TestSimulationBudgetRule_AllowNoBudgetRepo(t *testing.T) {
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success: true,
			BalanceChanges: []simulation.BalanceChange{
				{
					Token:     "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
					Standard:  "erc20",
					Amount:    big.NewInt(-2300000000),
					Direction: "outflow",
				},
			},
		},
	}
	// No budget repo -> budget check passes through
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	to := "0x1234567890abcdef1234567890abcdef12345678"
	val := "0"
	outcome, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		SignType:      SignTypeTransaction,
	}, &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	})
	require.NoError(t, err)
	assert.Equal(t, "allow", outcome.Decision)
}

func TestSimulationBudgetRule_BatchApproveAndSwap_TracksBudget(t *testing.T) {
	// Batch: approve (non-zero value) + swap (value=0 side effect).
	// Approve tx has real Approval event → entire batch needs manual approval.
	sim := &mockSimulator{
		simulateBatchResult: &simulation.BatchSimulationResult{
			Results: []simulation.SimulationResult{
				{Success: true, HasApproval: true, Events: []simulation.SimEvent{
					{Event: "Approval", Args: map[string]string{"owner": "0x764602fead618416e42b48c633d90869ff19759e", "value": "1000000"}},
				}},
				{
					Success:     true,
					HasApproval: true,
					Events: []simulation.SimEvent{
						{Event: "Approval", Args: map[string]string{"owner": "0x764602fead618416e42b48c633d90869ff19759e", "value": "0"}}, // transferFrom side effect
					},
					BalanceChanges: []simulation.BalanceChange{
						{Token: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", Amount: big.NewInt(-1000000), Direction: "outflow"},
						{Token: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", Amount: big.NewInt(999989), Direction: "inflow"},
					},
				},
			},
			NetBalanceChanges: []simulation.BalanceChange{
				{Token: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", Amount: big.NewInt(-1000000), Direction: "outflow"},
				{Token: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", Amount: big.NewInt(999989), Direction: "inflow"},
			},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	txParams := []simulation.TxParams{
		{To: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", Value: "0", Data: "0x095ea7b3"},
		{To: "0x057cfd839aa88994d1a8a8c6d336cf21550f05ef", Value: "0", Data: "0xf2c42696"},
	}
	outcome, err := r.EvaluateBatch(context.Background(), "137", "0x764602FeaD618416E42b48c633d90869fF19759E", txParams)
	require.NoError(t, err)
	// Budget passes (no repo), but approval detected → manual approval required
	assert.Equal(t, "no_match", outcome.Decision)
	assert.NotNil(t, outcome.Simulation)
}

func TestSimulationBudgetRule_BatchReverted(t *testing.T) {
	sim := &mockSimulator{
		simulateBatchResult: &simulation.BatchSimulationResult{
			Results: []simulation.SimulationResult{
				{Success: true},
				{Success: false, RevertReason: "out of gas"},
			},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	txParams := []simulation.TxParams{
		{To: "0x1234567890abcdef1234567890abcdef12345678", Value: "0"},
		{To: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", Value: "0"},
	}
	outcome, err := r.EvaluateBatch(context.Background(), "1", "0xf39F", txParams)
	require.NoError(t, err)
	assert.Equal(t, "deny", outcome.Decision)
}

func TestSimulationBudgetRule_BatchAllowNoBudget(t *testing.T) {
	sim := &mockSimulator{
		simulateBatchResult: &simulation.BatchSimulationResult{
			Results: []simulation.SimulationResult{
				{Success: true},
				{
					Success: true,
					BalanceChanges: []simulation.BalanceChange{
						{Token: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", Amount: big.NewInt(-100), Direction: "outflow"},
					},
				},
			},
			NetBalanceChanges: []simulation.BalanceChange{
				{Token: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", Amount: big.NewInt(-100), Direction: "outflow"},
			},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	txParams := []simulation.TxParams{
		{To: "0x1234567890abcdef1234567890abcdef12345678", Value: "0"},
		{To: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", Value: "0"},
	}
	outcome, err := r.EvaluateBatch(context.Background(), "1", "0xf39F", txParams)
	require.NoError(t, err)
	assert.Equal(t, "allow", outcome.Decision)
}

func TestSimulationBudgetRule_BatchEmpty(t *testing.T) {
	sim := &mockSimulator{}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	_, err = r.EvaluateBatch(context.Background(), "1", "0xf39F", nil)
	assert.Error(t, err, "expected error for empty batch")
}

func TestExtractTxParamsForSimulation(t *testing.T) {
	to := "0x5E1f62Dac767b0491e3CE72469C217365D5B48cC"
	val := "1000000000000000000" // 1 ETH in wei
	sig := "0xf2c42696"
	rawData := []byte{0xf2, 0xc4, 0x26, 0x96}

	parsed := &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
		MethodSig: &sig,
		RawData:   rawData,
	}

	gotTo, gotValue, gotData, _, err := extractTxParamsForSimulation(parsed)
	require.NoError(t, err)
	assert.Equal(t, to, gotTo)
	assert.Equal(t, "0xde0b6b3a7640000", gotValue)
	assert.Equal(t, "0xf2c42696", gotData)
}

func TestExtractTxParamsForSimulation_NilParsed(t *testing.T) {
	_, _, _, _, err := extractTxParamsForSimulation(nil)
	assert.Error(t, err)
}

func TestNewSimulationBudgetRule_NilLogger(t *testing.T) {
	_, err := NewSimulationBudgetRule(nil, nil, nil, nil, nil, nil, nil)
	assert.Error(t, err, "expected error for nil logger")
}

func TestSimulationBudgetRule_GasCostEstimation(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	// EIP-1559 tx with gasFeeCap
	payload1559 := []byte(`{"transaction":{"to":"0x1234567890abcdef1234567890abcdef12345678","value":"0","data":"0x","gas":21000,"gasFeeCap":"50000000000","gasTipCap":"1000000000","txType":"eip1559"}}`)
	gasCost := r.estimateGasCost(21000, payload1559)
	require.NotNil(t, gasCost)
	// 21000 * 50000000000 = 1050000000000000 (1.05e15 wei)
	expected := new(big.Int).Mul(big.NewInt(21000), big.NewInt(50000000000))
	assert.Equal(t, expected.String(), gasCost.String())

	// Legacy tx with gasPrice
	payloadLegacy := []byte(`{"transaction":{"to":"0x1234567890abcdef1234567890abcdef12345678","value":"0","data":"0x","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`)
	gasCost2 := r.estimateGasCost(21000, payloadLegacy)
	require.NotNil(t, gasCost2)
	expected2 := new(big.Int).Mul(big.NewInt(21000), big.NewInt(20000000000))
	assert.Equal(t, expected2.String(), gasCost2.String())

	// Zero gasUsed -> nil
	assert.Nil(t, r.estimateGasCost(0, payloadLegacy))

	// Empty payload -> nil
	assert.Nil(t, r.estimateGasCost(21000, nil))

	// gasPrice=0 -> nil (no cost)
	payloadZero := []byte(`{"transaction":{"to":"0x1234","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`)
	assert.Nil(t, r.estimateGasCost(21000, payloadZero))
}

func TestAppendGasCostToBalanceChanges(t *testing.T) {
	gasCost := big.NewInt(1050000000000000) // 1.05e15 wei

	// Case 1: No existing native outflow → new entry added
	changes := []simulation.BalanceChange{
		{Token: "0xusdc", Standard: "erc20", Amount: big.NewInt(-1000000), Direction: "outflow"},
	}
	result := appendGasCostToBalanceChanges(changes, gasCost)
	assert.Len(t, result, 2)
	assert.Equal(t, "native", result[1].Token)
	assert.Equal(t, new(big.Int).Neg(gasCost).String(), result[1].Amount.String())

	// Case 2: Existing native outflow → merged
	changes2 := []simulation.BalanceChange{
		{Token: "native", Standard: "native", Amount: big.NewInt(-500000000000000), Direction: "outflow"},
	}
	result2 := appendGasCostToBalanceChanges(changes2, gasCost)
	assert.Len(t, result2, 1)
	expectedMerged := new(big.Int).Sub(big.NewInt(-500000000000000), gasCost)
	assert.Equal(t, expectedMerged.String(), result2[0].Amount.String())

	// Original should not be mutated
	assert.Equal(t, big.NewInt(-500000000000000).String(), changes2[0].Amount.String())
}

func TestSimulationBudgetRule_EvaluateSingle_WithGasCost(t *testing.T) {
	// Verify that EvaluateSingle includes gas cost in budget check.
	// Use a simulation with gasUsed=100000, and a payload with gasFeeCap=100 Gwei.
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success: true,
			GasUsed: 100000,
			BalanceChanges: []simulation.BalanceChange{
				{Token: "0xusdc", Standard: "erc20", Amount: big.NewInt(-1000000), Direction: "outflow"},
			},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	to := "0x1234567890abcdef1234567890abcdef12345678"
	val := "0"
	outcome, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x1234567890abcdef1234567890abcdef12345678","value":"0","data":"0xa9059cbb","gas":100000,"gasFeeCap":"100000000000","gasTipCap":"1000000000","txType":"eip1559"}}`),
	}, &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	})
	require.NoError(t, err)
	// No budget repo → passes through → allow
	assert.Equal(t, "allow", outcome.Decision)
}

// --- Mock types for ENH-2 and IMP-3 tests ---

// mockSimBudgetRepo implements storage.BudgetRepository for simulation budget tests.
type mockSimBudgetRepo struct {
	mu       sync.Mutex
	budgets  map[string]*types.RuleBudget // key: ruleID + ":" + unit
	countMap map[types.RuleID]int         // override for CountByRuleID
}

func newMockSimBudgetRepo() *mockSimBudgetRepo {
	return &mockSimBudgetRepo{
		budgets:  make(map[string]*types.RuleBudget),
		countMap: make(map[types.RuleID]int),
	}
}

func (m *mockSimBudgetRepo) Create(_ context.Context, budget *types.RuleBudget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(budget.RuleID) + ":" + budget.Unit
	m.budgets[key] = budget
	return nil
}

func (m *mockSimBudgetRepo) CreateOrGet(_ context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(budget.RuleID) + ":" + budget.Unit
	if existing, ok := m.budgets[key]; ok {
		return existing, false, nil
	}
	now := time.Now()
	budget.CreatedAt = now
	budget.UpdatedAt = now
	m.budgets[key] = budget
	return budget, true, nil
}

func (m *mockSimBudgetRepo) GetByRuleID(_ context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(ruleID) + ":" + unit
	if b, ok := m.budgets[key]; ok {
		cp := *b
		return &cp, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockSimBudgetRepo) CountByRuleID(_ context.Context, ruleID types.RuleID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cnt, ok := m.countMap[ruleID]; ok {
		return cnt, nil
	}
	// Count actual budgets
	count := 0
	prefix := string(ruleID) + ":"
	for key := range m.budgets {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			count++
		}
	}
	return count, nil
}

func (m *mockSimBudgetRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, b := range m.budgets {
		if b.ID == id {
			delete(m.budgets, key)
			return nil
		}
	}
	return nil
}
func (m *mockSimBudgetRepo) DeleteByRuleID(_ context.Context, _ types.RuleID) error { return nil }
func (m *mockSimBudgetRepo) AtomicSpend(_ context.Context, _ types.RuleID, _ string, _ string) error {
	return nil
}
func (m *mockSimBudgetRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error {
	return nil
}
func (m *mockSimBudgetRepo) ListByRuleID(_ context.Context, _ types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *mockSimBudgetRepo) ListByRuleIDs(_ context.Context, _ []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *mockSimBudgetRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error {
	return nil
}

// setCount overrides CountByRuleID for a specific ruleID.
func (m *mockSimBudgetRepo) setCount(ruleID types.RuleID, count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countMap[ruleID] = count
}

// mockDecimalsQuerier implements rule.DecimalsQuerier for testing.
type mockDecimalsQuerier struct {
	decimals map[string]int   // key: chainID + ":" + address
	errs     map[string]error // key: chainID + ":" + address
}

func newMockDecimalsQuerier() *mockDecimalsQuerier {
	return &mockDecimalsQuerier{
		decimals: make(map[string]int),
		errs:     make(map[string]error),
	}
}

func (m *mockDecimalsQuerier) setDecimals(chainID, address string, d int) {
	m.decimals[chainID+":"+address] = d
}

func (m *mockDecimalsQuerier) QueryDecimals(_ context.Context, chainID, address string) (int, error) {
	key := chainID + ":" + address
	if err, ok := m.errs[key]; ok {
		return 0, err
	}
	if d, ok := m.decimals[key]; ok {
		return d, nil
	}
	return 0, fmt.Errorf("decimals not configured for %s", key)
}

// mockDecimalsAlerter implements DecimalsAnomalyAlerter for testing.
type mockDecimalsAlerter struct {
	mu     sync.Mutex
	alerts []decimalsAlert
}

type decimalsAlert struct {
	ChainID  string
	Token    string
	Decimals int
	Reason   string
}

func (m *mockDecimalsAlerter) AlertDecimalsAnomaly(_ context.Context, chainID, token string, decimals int, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, decimalsAlert{
		ChainID:  chainID,
		Token:    token,
		Decimals: decimals,
		Reason:   reason,
	})
}

func (m *mockDecimalsAlerter) alertCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.alerts)
}

// --- ENH-2 Tests: MaxDynamicUnits ---

func TestAutoCreateBudget_StopsAtMaxDynamicUnits(t *testing.T) {
	repo := newMockSimBudgetRepo()
	defaults := &SimBudgetDefaults{
		ERC20MaxTotal:   "100",
		ERC20MaxPerTx:   "50",
		MaxDynamicUnits: 2,
	}
	dq := newMockDecimalsQuerier()
	dq.setDecimals("1", "0xtoken1", 6)
	dq.setDecimals("1", "0xtoken2", 6)
	dq.setDecimals("1", "0xtoken3", 6)

	r, err := NewSimulationBudgetRule(&mockSimulator{}, repo, defaults, dq, nil, nil, simTestLogger())
	require.NoError(t, err)

	syntheticRuleID := types.RuleID("sim:0xsigner")

	// First token: should succeed
	b1, err := r.autoCreateBudget(context.Background(), "1", "0xsigner", "0xtoken1", syntheticRuleID, "1:0xtoken1")
	require.NoError(t, err)
	require.NotNil(t, b1)

	// Second token: should succeed (count is now 1)
	b2, err := r.autoCreateBudget(context.Background(), "1", "0xsigner", "0xtoken2", syntheticRuleID, "1:0xtoken2")
	require.NoError(t, err)
	require.NotNil(t, b2)

	// Third token: should fail (count is now 2, limit is 2)
	b3, err := r.autoCreateBudget(context.Background(), "1", "0xsigner", "0xtoken3", syntheticRuleID, "1:0xtoken3")
	assert.Error(t, err)
	assert.Nil(t, b3)
	assert.Contains(t, err.Error(), "simulation budget unit limit reached")
}

func TestAutoCreateBudget_WithinLimitStillWorks(t *testing.T) {
	repo := newMockSimBudgetRepo()
	defaults := &SimBudgetDefaults{
		NativeMaxTotal: "1",
		NativeMaxPerTx: "0.5",
	}

	r, err := NewSimulationBudgetRule(&mockSimulator{}, repo, defaults, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	syntheticRuleID := types.RuleID("sim:0xsigner")

	// Native token with count=0, default limit=100 -> should succeed
	b, err := r.autoCreateBudget(context.Background(), "1", "0xsigner", "native", syntheticRuleID, "1:native")
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "1000000000000000000", b.MaxTotal) // 1 ETH = 1e18
}

func TestAutoCreateBudget_DefaultMaxDynamicUnits(t *testing.T) {
	// Verify default of 100 is used when MaxDynamicUnits is 0
	repo := newMockSimBudgetRepo()
	defaults := &SimBudgetDefaults{
		ERC20MaxTotal: "100",
		ERC20MaxPerTx: "50",
		// MaxDynamicUnits: 0 -> use default 100
	}
	dq := newMockDecimalsQuerier()
	dq.setDecimals("1", "0xtoken", 6)

	r, err := NewSimulationBudgetRule(&mockSimulator{}, repo, defaults, dq, nil, nil, simTestLogger())
	require.NoError(t, err)

	// Set count to 100 (at limit)
	syntheticRuleID := types.RuleID("sim:0xsigner")
	repo.setCount(syntheticRuleID, 100)

	b, err := r.autoCreateBudget(context.Background(), "1", "0xsigner", "0xtoken", syntheticRuleID, "1:0xtoken")
	assert.Error(t, err)
	assert.Nil(t, b)
	assert.Contains(t, err.Error(), "simulation budget unit limit reached (100/100)")
}

// --- IMP-3 Tests: Decimals Anomaly Alert ---

func TestAutoCreateBudget_AnomalousDecimals_Alerts(t *testing.T) {
	tests := []struct {
		name      string
		decimals  int
		wantAlert bool
	}{
		{"decimals_0_alerts", 0, true},
		{"decimals_25_alerts", 25, true},
		{"decimals_77_alerts", 77, true},
		{"decimals_6_no_alert", 6, false},
		{"decimals_18_no_alert", 18, false},
		{"decimals_24_no_alert", 24, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockSimBudgetRepo()
			defaults := &SimBudgetDefaults{
				ERC20MaxTotal: "100",
				ERC20MaxPerTx: "50",
			}
			dq := newMockDecimalsQuerier()
			dq.setDecimals("1", "0xtoken", tt.decimals)

			alerter := &mockDecimalsAlerter{}

			r, err := NewSimulationBudgetRule(&mockSimulator{}, repo, defaults, dq, nil, nil, simTestLogger())
			require.NoError(t, err)
			r.SetDecimalsAlerter(alerter)

			syntheticRuleID := types.RuleID("sim:0xsigner")
			_, err = r.autoCreateBudget(context.Background(), "1", "0xsigner", "0xtoken", syntheticRuleID, "1:0xtoken")
			require.NoError(t, err)

			if tt.wantAlert {
				assert.Equal(t, 1, alerter.alertCount(), "expected anomaly alert for decimals=%d", tt.decimals)
			} else {
				assert.Equal(t, 0, alerter.alertCount(), "expected no alert for decimals=%d", tt.decimals)
			}
		})
	}
}

func TestAutoCreateBudget_NativeToken_NoDecimalsAlert(t *testing.T) {
	// Native tokens always use decimals=18, should never trigger anomaly alert
	repo := newMockSimBudgetRepo()
	defaults := &SimBudgetDefaults{
		NativeMaxTotal: "1",
		NativeMaxPerTx: "0.5",
	}
	alerter := &mockDecimalsAlerter{}

	r, err := NewSimulationBudgetRule(&mockSimulator{}, repo, defaults, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	r.SetDecimalsAlerter(alerter)

	syntheticRuleID := types.RuleID("sim:0xsigner")
	_, err = r.autoCreateBudget(context.Background(), "1", "0xsigner", "native", syntheticRuleID, "1:native")
	require.NoError(t, err)
	assert.Equal(t, 0, alerter.alertCount())
}

func TestCheckBudgetFromBalanceChanges_DenyOnUnitLimitReached(t *testing.T) {
	// End-to-end test: checkBudgetFromBalanceChanges should return error when unit limit reached
	repo := newMockSimBudgetRepo()
	defaults := &SimBudgetDefaults{
		ERC20MaxTotal:   "100",
		ERC20MaxPerTx:   "50",
		MaxDynamicUnits: 1,
	}
	dq := newMockDecimalsQuerier()
	dq.setDecimals("1", "0xtoken_a", 6)
	dq.setDecimals("1", "0xtoken_b", 6)

	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success: true,
			BalanceChanges: []simulation.BalanceChange{
				{Token: "0xtoken_a", Standard: "erc20", Amount: big.NewInt(-1000000), Direction: "outflow"},
			},
		},
	}

	r, err := NewSimulationBudgetRule(sim, repo, defaults, dq, nil, nil, simTestLogger())
	require.NoError(t, err)

	to := "0x1234567890abcdef1234567890abcdef12345678"
	val := "0"

	// First request: creates budget for token_a -> should allow
	outcome1, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0xSigner",
		SignType:      SignTypeTransaction,
	}, &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	})
	require.NoError(t, err)
	assert.Equal(t, "allow", outcome1.Decision)

	// Second request with different token: should deny (unit limit=1 reached)
	sim.simulateResult = &simulation.SimulationResult{
		Success: true,
		BalanceChanges: []simulation.BalanceChange{
			{Token: "0xtoken_b", Standard: "erc20", Amount: big.NewInt(-500000), Direction: "outflow"},
		},
	}

	outcome2, err := r.EvaluateSingle(context.Background(), &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0xSigner",
		SignType:      SignTypeTransaction,
	}, &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	})
	require.NoError(t, err)
	assert.Equal(t, "deny", outcome2.Decision)
	assert.Contains(t, outcome2.Reason, "simulation budget unit limit reached")
}

// Ensure unused import for storage.ErrBudgetExceeded (used by mock)
var _ = storage.ErrBudgetExceeded

// ─────────────────────────────────────────────────────────────────────────────
// V3-6: Simulation autoCreateBudget TOCTOU — post-create verification
// ─────────────────────────────────────────────────────────────────────────────

// TestAutoCreateBudget_TOCTOU_ConcurrentUnitsRespectMax verifies that concurrent
// creation of simulation budget units for different tokens respects MaxDynamicUnits.
func TestAutoCreateBudget_TOCTOU_ConcurrentUnitsRespectMax(t *testing.T) {
	const maxUnits = 3
	const numGoroutines = 10

	repo := newMockSimBudgetRepo()
	defaults := &SimBudgetDefaults{
		ERC20MaxTotal:   "100",
		ERC20MaxPerTx:   "50",
		MaxDynamicUnits: maxUnits,
	}
	dq := newMockDecimalsQuerier()
	for i := 0; i < numGoroutines; i++ {
		dq.setDecimals("1", fmt.Sprintf("0xtoken%d", i), 6)
	}

	r, err := NewSimulationBudgetRule(&mockSimulator{}, repo, defaults, dq, nil, nil, simTestLogger())
	require.NoError(t, err)

	syntheticRuleID := types.RuleID("sim:0xsigner")

	var wg sync.WaitGroup
	var successCount int32
	var errorCount int32

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := fmt.Sprintf("0xtoken%d", idx)
			unit := fmt.Sprintf("1:%s", token)
			_, createErr := r.autoCreateBudget(context.Background(), "1", "0xsigner", token, syntheticRuleID, unit)
			if createErr != nil {
				atomic.AddInt32(&errorCount, 1)
			} else {
				atomic.AddInt32(&successCount, 1)
			}
		}(i)
	}
	wg.Wait()

	// Count actual budgets stored
	repo.mu.Lock()
	finalCount := 0
	for key := range repo.budgets {
		if len(key) > len(string(syntheticRuleID))+1 && key[:len(string(syntheticRuleID))+1] == string(syntheticRuleID)+":" {
			finalCount++
		}
	}
	repo.mu.Unlock()

	t.Logf("successes=%d errors=%d final_budget_count=%d", successCount, errorCount, finalCount)

	assert.LessOrEqual(t, finalCount, maxUnits,
		"final budget count must not exceed MaxDynamicUnits (%d), got %d", maxUnits, finalCount)
	assert.Greater(t, int(successCount), 0, "at least one goroutine should succeed")
	assert.Greater(t, int(errorCount), 0, "excess goroutines should fail")
}
