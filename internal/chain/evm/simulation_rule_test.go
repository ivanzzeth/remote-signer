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
func (m *mockSimulator) Close() error                                   { return nil }

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

func TestSimulationBudgetRule_ApprovalDetected_ReturnsNoMatch(t *testing.T) {
	sim := &mockSimulator{
		simulateResult: &simulation.SimulationResult{
			Success:     true,
			HasApproval: true,
			Events: []simulation.SimEvent{
				{Event: "Approval", Standard: "erc20"},
			},
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
	// Approval detected -> returns no_match so existing manual approval flow handles it
	assert.Equal(t, "no_match", outcome.Decision)
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

func TestSimulationBudgetRule_BatchApprovalDetected_ReturnsNoMatch(t *testing.T) {
	sim := &mockSimulator{
		simulateBatchResult: &simulation.BatchSimulationResult{
			Results: []simulation.SimulationResult{
				{Success: true, HasApproval: true},
				{Success: true, HasApproval: false},
			},
			NetBalanceChanges: []simulation.BalanceChange{},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
	require.NoError(t, err)

	txParams := []simulation.TxParams{
		{To: "0xabc", Value: "0", Data: "0x095ea7b3"},
		{To: "0xdef", Value: "0", Data: "0xf2c42696"},
	}
	outcome, err := r.EvaluateBatch(context.Background(), "1", "0xf39F", txParams)
	require.NoError(t, err)
	assert.Equal(t, "no_match", outcome.Decision)
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
		{To: "0xabc", Value: "0"},
		{To: "0xdef", Value: "0"},
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
						{Token: "0xusdc", Amount: big.NewInt(-100), Direction: "outflow"},
					},
				},
			},
			NetBalanceChanges: []simulation.BalanceChange{
				{Token: "0xusdc", Amount: big.NewInt(-100), Direction: "outflow"},
			},
		},
	}
	r, err := NewSimulationBudgetRule(sim, nil, simTestLogger())
	require.NoError(t, err)

	txParams := []simulation.TxParams{
		{To: "0xabc", Value: "0"},
		{To: "0xdef", Value: "0"},
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
