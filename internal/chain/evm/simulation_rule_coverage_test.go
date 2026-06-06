package evm

import (
	"context"
	"math/big"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- contractsFromEvents ---

func TestContractsFromEvents_Empty(t *testing.T) {
	assert.Nil(t, contractsFromEvents(nil))
	assert.Nil(t, contractsFromEvents([]simulation.SimEvent{}))
}

func TestContractsFromEvents_Single(t *testing.T) {
	events := []simulation.SimEvent{
		{Address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", Event: "Transfer"},
	}
	result := contractsFromEvents(events)
	assert.Equal(t, []string{"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"}, result)
}

func TestContractsFromEvents_DedupAndSort(t *testing.T) {
	events := []simulation.SimEvent{
		{Address: "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},
		{Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{Address: "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},
	}
	result := contractsFromEvents(events)
	assert.Len(t, result, 2)
	assert.Equal(t, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", result[0])
	assert.Equal(t, "0xcccccccccccccccccccccccccccccccccccccccc", result[1])
}

// --- humanToRaw edge cases ---

func TestHumanToRaw_Unlimited(t *testing.T) {
	assert.Equal(t, "-1", humanToRaw("-1", 18))
	assert.Equal(t, "", humanToRaw("", 6))
}

func TestHumanToRaw_FractionLongerThanDecimals(t *testing.T) {
	assert.Equal(t, "1234567", humanToRaw("1.234567890", 6))
}

func TestHumanToRaw_Zero(t *testing.T) {
	assert.Equal(t, "0", humanToRaw("0", 18))
	assert.Equal(t, "0", humanToRaw("0.0", 6))
}

func TestHumanToRaw_NoFraction(t *testing.T) {
	assert.Equal(t, "1000000", humanToRaw("1", 6))
}

func TestHumanToRaw_PadFraction(t *testing.T) {
	assert.Equal(t, "1500000", humanToRaw("1.5", 6))
}

// --- NewRPCAllowanceQuerier ---

func TestNewRPCAllowanceQuerier_NilProvider(t *testing.T) {
	assert.Nil(t, NewRPCAllowanceQuerier(nil))
}

func TestNewRPCAllowanceQuerier_NonNilProvider(t *testing.T) {
	provider, err := NewRPCProvider("http://localhost:1", "")
	require.NoError(t, err)
	q := NewRPCAllowanceQuerier(provider)
	assert.NotNil(t, q)
}

// --- SetSimulationRepo / recordOutcome ---

type stubSimulationRepo struct {
	upserts int
}

func (s *stubSimulationRepo) Upsert(_ context.Context, _ *types.RequestSimulation) error {
	s.upserts++
	return nil
}
func (s *stubSimulationRepo) GetByRequestID(_ context.Context, _ string) (*types.RequestSimulation, error) {
	return nil, types.ErrNotFound
}
func (s *stubSimulationRepo) List(_ context.Context, _ storage.ListRequestSimulationsFilter) ([]*types.RequestSimulation, bool, error) {
	return nil, false, nil
}

func TestRecordOutcome_NilRepo(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	r.recordOutcome(context.Background(), &types.SignRequest{ID: "req1"}, nil,
		&SimulationOutcome{Decision: "allow", Simulation: &simulation.SimulationResult{Success: true}})
}

func TestRecordOutcome_NilOutcome(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	r.recordOutcome(context.Background(), &types.SignRequest{ID: "req1"}, nil, nil)
}

func TestRecordOutcome_NilReq(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	r.recordOutcome(context.Background(), nil, nil,
		&SimulationOutcome{Decision: "allow", Simulation: &simulation.SimulationResult{Success: true}})
}

func TestRecordOutcome_NilSimulation(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	r.recordOutcome(context.Background(), &types.SignRequest{ID: "req1"}, nil,
		&SimulationOutcome{Decision: "no_match"})
}

func TestRecordOutcome_WithRepo(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	repo := &stubSimulationRepo{}
	r.SetSimulationRepo(repo)

	r.recordOutcome(context.Background(),
		&types.SignRequest{ID: "req1", ChainID: "1"},
		nil,
		&SimulationOutcome{
			Decision: "allow",
			Simulation: &simulation.SimulationResult{
				Success: true,
				GasUsed: 21000,
				Events: []simulation.SimEvent{
					{Address: "0xabc", Event: "Transfer"},
				},
				BalanceChanges: []simulation.BalanceChange{
					{Token: "native", Amount: big.NewInt(-100000), Direction: "outflow"},
				},
			},
		})
	assert.Equal(t, 1, repo.upserts)
}

func TestRecordOutcome_Reverted(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	repo := &stubSimulationRepo{}
	r.SetSimulationRepo(repo)

	r.recordOutcome(context.Background(),
		&types.SignRequest{ID: "req2", ChainID: "137"},
		nil,
		&SimulationOutcome{
			Decision: "deny",
			Simulation: &simulation.SimulationResult{
				Success:      false,
				RevertReason: "execution reverted",
				GasUsed:      50000,
			},
		})
	assert.Equal(t, 1, repo.upserts)
}

// --- estimateGasCost edge cases ---

func TestEstimateGasCost_HexGasPrice(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	payload := []byte(`{"transaction":{"to":"0x1234","value":"0","data":"0x","gas":21000,"gasPrice":"0x4a817c800","txType":"legacy"}}`)
	gasCost := r.estimateGasCost(21000, payload)
	require.NotNil(t, gasCost)
	assert.Equal(t, "420000000000000", gasCost.String())
}

func TestEstimateGasCost_HexGasFeeCap(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)

	payload := []byte(`{"transaction":{"to":"0x1234","value":"0","data":"0x","gas":50000,"gasFeeCap":"0x174876e800","gasTipCap":"0x3b9aca00","txType":"eip1559"}}`)
	gasCost := r.estimateGasCost(50000, payload)
	require.NotNil(t, gasCost)
	assert.Equal(t, "5000000000000000", gasCost.String())
}

func TestEstimateGasCost_NoTransactionField(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	assert.Nil(t, r.estimateGasCost(21000, []byte(`{}`)))
}

func TestEstimateGasCost_InvalidGasPriceString(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	payload := []byte(`{"transaction":{"to":"0x1234","value":"0","data":"0x","gas":21000,"gasPrice":"not_a_number","txType":"legacy"}}`)
	assert.Nil(t, r.estimateGasCost(21000, payload))
}

func TestEstimateGasCost_EIP1559OverLegacy(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	payload := []byte(`{"transaction":{"to":"0x1234","value":"0","data":"0x","gas":10000,"gasFeeCap":"100000000000","gasPrice":"50000000000","gasTipCap":"1000000000","txType":"eip1559"}}`)
	gasCost := r.estimateGasCost(10000, payload)
	require.NotNil(t, gasCost)
	assert.Equal(t, "1000000000000000", gasCost.String())
}

func TestEstimateGasCost_InvalidJSON(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	assert.Nil(t, r.estimateGasCost(21000, []byte(`{bad json`)))
}

// --- NewEVMAdapterSignerLister ---

func TestNewEVMAdapterSignerLister(t *testing.T) {
	adapter, err := NewEVMAdapter(NewEmptySignerRegistry())
	require.NoError(t, err)
	l := NewEVMAdapterSignerLister(adapter)
	assert.NotNil(t, l)
}

// --- StaticSimBudgetPolicy ---

func TestStaticSimBudgetPolicy_Defaults(t *testing.T) {
	defaults := &SimBudgetDefaults{
		NativeMaxTotal:  "1",
		NativeMaxPerTx:  "0.5",
		ERC20MaxTotal:   "100",
		ERC20MaxPerTx:   "50",
		MaxDynamicUnits: 50,
	}
	p := NewStaticSimBudgetPolicy(true, defaults)
	assert.True(t, p.AutoCreate())
	assert.Equal(t, defaults, p.Defaults())
}

func TestStaticSimBudgetPolicy_NilDefaults(t *testing.T) {
	p := NewStaticSimBudgetPolicy(false, nil)
	assert.False(t, p.AutoCreate())
	assert.Nil(t, p.Defaults())
}

// --- SetDecimalsAlerter ---

func TestSimulationBudgetRule_SetDecimalsAlerter(t *testing.T) {
	r, err := NewSimulationBudgetRule(&mockSimulator{}, nil, nil, nil, nil, nil, simTestLogger())
	require.NoError(t, err)
	assert.Nil(t, r.decimalsAlerter)

	alerter := &mockDecimalsAlerter{}
	r.SetDecimalsAlerter(alerter)
	assert.NotNil(t, r.decimalsAlerter)
}

// --- SimBudgetDefaults zero MaxDynamicUnits ---

func TestAutoCreateBudget_UsesDefaultsZeroMaxUnits(t *testing.T) {
	repo := newMockSimBudgetRepo()
	defaults := &SimBudgetDefaults{
		ERC20MaxTotal: "100",
		ERC20MaxPerTx: "50",
	}
	dq := newMockDecimalsQuerier()
	dq.setDecimals("1", "0xtoken", 6)

	r, err := NewSimulationBudgetRule(&mockSimulator{}, repo,
		NewStaticSimBudgetPolicy(true, defaults), dq, nil, nil, simTestLogger())
	require.NoError(t, err)

	// With 0 units, should use default (100) → should succeed
	b, err := r.autoCreateBudget(context.Background(), "1", "0xsigner", "0xtoken",
		types.RuleID("sim:0xsigner"), "1:0xtoken")
	require.NoError(t, err)
	require.NotNil(t, b)
}

// --- extractTxParamsForSimulation hex value ---

func TestExtractTxParamsForSimulation_HexValue(t *testing.T) {
	to := "0xTarget"
	val := "0xde0b6b3a7640000"
	parsed := &types.ParsedPayload{
		Recipient: &to,
		Value:     &val,
	}
	gotTo, gotValue, _, _, err := extractTxParamsForSimulation(parsed)
	require.NoError(t, err)
	assert.Equal(t, to, gotTo)
	assert.Equal(t, "0xde0b6b3a7640000", gotValue)
}

// --- checkBudgetFromBalanceChanges: per-tx limit ---

func TestCheckBudgetFromBalanceChanges_PerTxExceeded(t *testing.T) {
	repo := newMockSimBudgetRepo()
	defaults := &SimBudgetDefaults{ERC20MaxTotal: "1000", ERC20MaxPerTx: "10"}
	dq := newMockDecimalsQuerier()
	dq.setDecimals("1", "0xtoken", 6) // 6 decimals, so maxPerTx = 10_000000

	r, err := NewSimulationBudgetRule(&mockSimulator{}, repo,
		NewStaticSimBudgetPolicy(true, defaults), dq, nil, nil, simTestLogger())
	require.NoError(t, err)

	syntheticRuleID := types.RuleID("sim:0xsigner")

	// Pre-create budget so auto-create is skipped. Use the repo directly.
	_, _, err = repo.CreateOrGet(context.Background(), &types.RuleBudget{
		ID:       types.BudgetID(syntheticRuleID, "1:0xtoken"),
		RuleID:   syntheticRuleID,
		Unit:     "1:0xtoken",
		MaxTotal: "100000000", // 100 tokens
		MaxPerTx: "5000000",   // 5 tokens
	})
	require.NoError(t, err)

	// Try to spend 10 tokens (> 5 token per-tx limit)
	err = r.checkBudgetFromBalanceChanges(context.Background(), "1", "0xsigner",
		[]simulation.BalanceChange{
			{Token: "0xtoken", Standard: "erc20", Amount: big.NewInt(-10000000), Direction: "outflow"}, // 10 tokens
		})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "per-tx limit")
}

// StdinPasswordProvider.GetPassword is not testable in automated testing
// because it requires an interactive terminal. Covered by existing
// TestNewStdinPasswordProvider_NotTerminal and integration tests.
