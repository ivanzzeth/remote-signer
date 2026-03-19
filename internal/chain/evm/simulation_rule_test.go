package evm

import (
	"context"
	"log/slog"
	"math/big"
	"os"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
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
	r, err := NewSimulationBudgetRule(nil, nil, simTestLogger())
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
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	// Pure approve tx: has approval event but zero balance outflow.
	// Budget passes (no outflow), but approval is security-sensitive → requires manual approval.
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success:     true,
			HasApproval: true,
			Events: []simulation.SimEvent{
				{Event: "Approval", Standard: "erc20"},
			},
			BalanceChanges: []simulation.BalanceChange{},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	// DEX swap tx: has internal approval event AND actual token outflow.
	// Budget should track the outflow, not skip because of approval.
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success:     true,
			HasApproval: true, // internal DEX approval
			Events: []simulation.SimEvent{
				{Event: "Approval", Standard: "erc20"},
				{Event: "Transfer", Standard: "erc20"},
			},
			BalanceChanges: []simulation.BalanceChange{
				{
					Token:     "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
					Standard:  "erc20",
					Amount:    big.NewInt(-1000000), // -1 USDC.e outflow
					Direction: "outflow",
				},
				{
					Token:     "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
					Standard:  "erc20",
					Amount:    big.NewInt(999989), // +0.999989 USDC inflow
					Direction: "inflow",
				},
			},
		},
	}
	// No budget repo -> budget passes through, but outflows are still processed
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	// Has approval event + outflow. Budget check runs (no repo = pass), then approval → manual approval.
	assert.Equal(t, "no_match", outcome.Decision)
	assert.NotNil(t, outcome.Simulation)
	assert.True(t, outcome.Simulation.HasApproval)
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
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	// Batch: approve + swap. Approve has no outflow, swap has outflow.
	// Budget should track the net outflow, not skip because of approval.
	sim := &mockSimulator{
		simulateBatchResult: &simulation.BatchSimulationResult{
			Results: []simulation.SimulationResult{
				{Success: true, HasApproval: true}, // approve tx
				{
					Success:     true,
					HasApproval: true, // swap has internal approval
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
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
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
	_, err := NewSimulationBudgetRule(nil, nil, nil)
	assert.Error(t, err, "expected error for nil logger")
}
