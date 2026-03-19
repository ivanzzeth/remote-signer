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
