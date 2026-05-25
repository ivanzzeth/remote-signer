//go:build integration

package simulation

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewRPCSimulator constructor tests
// ---------------------------------------------------------------------------

func TestNewRPCSimulator_NilLogger(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{RPCGatewayURL: "http://localhost:8545"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
	assert.Nil(t, sim)
}

func TestNewRPCSimulator_EmptyURL(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{}, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpc gateway URL is required")
	assert.Nil(t, sim)
}

func TestNewRPCSimulator_DefaultTimeout(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: "http://localhost:8545",
		Timeout:       0,
	}, testLogger())
	require.NoError(t, err)
	require.NotNil(t, sim)

	rs, ok := sim.(*rpcSimulator)
	require.True(t, ok, "expected *rpcSimulator")
	assert.Equal(t, 60*time.Second, rs.cfg.Timeout)
}

// ---------------------------------------------------------------------------
// normalizeHex tests
// ---------------------------------------------------------------------------

func TestNormalizeHex(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "0x0"},
		{"0", "0x0"},
		{"0x", "0x0"},
		{"0x0", "0x0"},
		{"0xff", "0xff"},
		{"ff", "0xff"},
		{"0x1234", "0x1234"},
		{"1234", "0x1234"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeHex(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// decodeRevertReason tests
// ---------------------------------------------------------------------------

func TestDecodeRevertReason_ErrorString(t *testing.T) {
	// ABI-encoded Error(string): 0x08c379a0
	// offset(32): 0x20 = 32
	// length(32): 0x0f = 15
	// data: "execution reverted" (15 chars = 30 hex chars)
	data := "0x08c379a0" +
		"0000000000000000000000000000000000000000000000000000000000000020" +
		"0000000000000000000000000000000000000000000000000000000000000012" +
		"657865637574696f6e2072657665727465640000000000000000000000000000"
	reason := decodeRevertReason(data)
	assert.Equal(t, "execution reverted", reason)
}

func TestDecodeRevertReason_ShortData(t *testing.T) {
	reason := decodeRevertReason("0x1234")
	assert.Equal(t, "transaction reverted", reason)
}

func TestDecodeRevertReason_UnknownSelector(t *testing.T) {
	data := "0xdeadbeef0000000000000000000000000000000000000000000000000000000000000000"
	reason := decodeRevertReason(data)
	assert.Contains(t, reason, "transaction reverted (0xdeadbeef...")
}

func TestDecodeRevertReason_ZeroXEmpty(t *testing.T) {
	reason := decodeRevertReason("0x")
	assert.Equal(t, "transaction reverted", reason)
}

func TestDecodeRevertReason_CustomReasonLong(t *testing.T) {
	// Test with a longer custom error string
	data := "0x08c379a0" +
		"0000000000000000000000000000000000000000000000000000000000000020" +
		"0000000000000000000000000000000000000000000000000000000000000016" +
		"696e73756666696369656e7420616c6c6f77616e636500000000000000000000"
	reason := decodeRevertReason(data)
	assert.Equal(t, "insufficient allowance", reason)
}

// ---------------------------------------------------------------------------
// hexDecode tests
// ---------------------------------------------------------------------------

func TestHexDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     []byte
		wantErr  bool
		errMsg   string
	}{
		{name: "even length", input: "deadbeef", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "odd length pads with 0", input: "abc", want: []byte{0x0a, 0xbc}},
		{name: "empty string", input: "", want: []byte{}},
		{name: "single char", input: "a", want: []byte{0x0a}},
		{name: "invalid char", input: "0xyz", wantErr: true, errMsg: "invalid hex char"},
		{name: "uppercase", input: "DEADBEEF", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "mixed case", input: "DeAdBeEf", want: []byte{0xde, 0xad, 0xbe, 0xef}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexDecode(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// hexVal tests
// ---------------------------------------------------------------------------

func TestHexVal(t *testing.T) {
	tests := []struct {
		c    byte
		want int
	}{
		{'0', 0}, {'1', 1}, {'5', 5}, {'9', 9},
		{'a', 10}, {'b', 11}, {'f', 15},
		{'A', 10}, {'B', 11}, {'F', 15},
		{'g', -1}, {'z', -1}, {'@', -1},
	}
	for _, tt := range tests {
		t.Run(string(tt.c), func(t *testing.T) {
			got := hexVal(tt.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// rpcSimulator no-op method tests
// ---------------------------------------------------------------------------

func TestRPCSimulator_Status(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: "http://localhost:8545",
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	status := sim.Status(context.Background())
	require.NotNil(t, status)
	assert.True(t, status.Enabled)
	assert.Equal(t, "rpc (eth_simulateV1)", status.EngineVersion)
	assert.NotNil(t, status.Chains)
	assert.Empty(t, status.Chains)
}

func TestRPCSimulator_Close(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: "http://localhost:8545",
	}, testLogger())
	require.NoError(t, err)
	err = sim.Close()
	assert.NoError(t, err)
}

func TestRPCSimulator_SyncIfDirty(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: "http://localhost:8545",
	}, testLogger())
	require.NoError(t, err)
	err = sim.SyncIfDirty(context.Background(), "1")
	assert.NoError(t, err)
}

func TestRPCSimulator_MarkDirty(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: "http://localhost:8545",
	}, testLogger())
	require.NoError(t, err)
	// Should not panic
	sim.MarkDirty("1")
}

// ---------------------------------------------------------------------------
// Simulate error paths
// ---------------------------------------------------------------------------

func TestSimulate_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty simulation response")
}

func TestSimulate_RPCServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"internal error"}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpc HTTP 500")
}

func TestSimulate_RPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpc error")
}

func TestSimulate_RevertResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x0","gasUsed":"0x5208","returnData":"0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012657865637574696f6e2072657665727465640000000000000000000000000000","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	result, err := sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "execution reverted", result.RevertReason)
}

func TestSimulate_GasSpecified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	result, err := sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
		Gas:     "0x100000",
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, uint64(21000), result.GasUsed)
}

// ---------------------------------------------------------------------------
// SimulateBatch tests
// ---------------------------------------------------------------------------

func TestSimulateBatch_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]},{"status":"0x1","gasUsed":"0x7530","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	result, err := sim.SimulateBatch(context.Background(), &BatchSimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Transactions: []TxParams{
			{To: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", Value: "0x0"},
			{To: "0x5e1f62dac767b0491e3ce72469c217365d5b48cc", Value: "0x0", Gas: "0x100000"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.Results, 2)
	assert.True(t, result.Results[0].Success)
	assert.True(t, result.Results[1].Success)
}

func TestSimulateBatch_MismatchedResponseLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.SimulateBatch(context.Background(), &BatchSimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Transactions: []TxParams{
			{To: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", Value: "0x0"},
			{To: "0x5e1f62dac767b0491e3ce72469c217365d5b48cc", Value: "0x0"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected simulation response")
}

func TestSimulateBatch_WithRevert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]},{"status":"0x0","gasUsed":"0x7530","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	result, err := sim.SimulateBatch(context.Background(), &BatchSimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Transactions: []TxParams{
			{To: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", Value: "0x0"},
			{To: "0x5e1f62dac767b0491e3ce72469c217365d5b48cc", Value: "0x0"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.Results, 2)
	assert.True(t, result.Results[0].Success)
	assert.False(t, result.Results[1].Success)
	assert.NotEmpty(t, result.Results[1].RevertReason)
}

func TestSimulateBatch_RPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.SimulateBatch(context.Background(), &BatchSimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Transactions: []TxParams{
			{To: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", Value: "0x0"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpc error")
}

// ---------------------------------------------------------------------------
// ethSimLogsToTxLogs test
// ---------------------------------------------------------------------------

func TestEthSimLogsToTxLogs(t *testing.T) {
	logs := []ethSimLog{
		{Address: "0xabc", Topics: []string{"0x123"}, Data: "0xdead"},
		{Address: "0xdef", Topics: []string{"0x456"}, Data: "0xbeef"},
	}
	result := ethSimLogsToTxLogs(logs)
	require.Len(t, result, 2)
	assert.Equal(t, "0xabc", result[0].Address)
	assert.Equal(t, "0xdef", result[1].Address)
}

// ---------------------------------------------------------------------------
// processERC1155Event tests
// ---------------------------------------------------------------------------

func TestProcessERC1155Event_TransferSingle(t *testing.T) {
	changes := make(map[balanceKey]*big.Int)
	signer := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

	event := SimEvent{
		Address:  "0x1234567890abcdef1234567890abcdef12345678",
		Event:    "TransferSingle",
		Standard: "erc1155",
		Args: map[string]string{
			"from":  signer,
			"to":    "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
			"id":    "42",
			"value": "100",
		},
	}

	processERC1155Event(event, signer, changes)
	require.Len(t, changes, 1)

	key := balanceKey{token: "0x1234567890abcdef1234567890abcdef12345678", tokenID: "42"}
	amount, ok := changes[key]
	require.True(t, ok, "expected balance key to exist")
	assert.Equal(t, big.NewInt(-100), amount) // outflow
}

func TestProcessERC1155Event_TransferBatch(t *testing.T) {
	changes := make(map[balanceKey]*big.Int)
	signer := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

	event := SimEvent{
		Address:  "0x1234567890abcdef1234567890abcdef12345678",
		Event:    "TransferBatch",
		Standard: "erc1155",
		Args: map[string]string{
			"from":  signer,
			"to":    "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
			"id":    "7",
			"value": "3",
		},
	}

	processERC1155Event(event, signer, changes)
	require.Len(t, changes, 1)

	key := balanceKey{token: "0x1234567890abcdef1234567890abcdef12345678", tokenID: "7"}
	amount, ok := changes[key]
	require.True(t, ok, "expected balance key to exist")
	assert.Equal(t, big.NewInt(-3), amount)
}

func TestProcessERC1155Event_Inflow(t *testing.T) {
	changes := make(map[balanceKey]*big.Int)
	signer := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

	event := SimEvent{
		Address:  "0x1234567890abcdef1234567890abcdef12345678",
		Event:    "TransferSingle",
		Standard: "erc1155",
		Args: map[string]string{
			"from":  "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
			"to":    signer,
			"id":    "1",
			"value": "5",
		},
	}

	processERC1155Event(event, signer, changes)
	require.Len(t, changes, 1)

	key := balanceKey{token: "0x1234567890abcdef1234567890abcdef12345678", tokenID: "1"}
	amount, ok := changes[key]
	require.True(t, ok, "expected balance key to exist")
	assert.Equal(t, big.NewInt(5), amount) // inflow
}

func TestProcessERC1155Event_WrongEventType(t *testing.T) {
	changes := make(map[balanceKey]*big.Int)
	event := SimEvent{
		Event:    "Transfer", // not TransferSingle or TransferBatch
		Standard: "erc1155",
	}
	processERC1155Event(event, "0xabc", changes)
	assert.Empty(t, changes, "should not process non-TransferSingle/TransferBatch events")
}

// ---------------------------------------------------------------------------
// parseTransferBatchData tests
// ---------------------------------------------------------------------------

func TestParseTransferBatchData_Valid(t *testing.T) {
	// ABI encoding: offset_ids(32) + offset_values(32) + len_ids(32) + ids... + len_values(32) + values...
	// ids offset = 0x40 (64 bytes into data = 0x80 hex chars)
	// values offset = 0x80 (128 bytes into data = 0x100 hex chars)
	// ids array: length=2, [1, 2]
	// values array: length=2, [100, 200]
	data :=
		"0000000000000000000000000000000000000000000000000000000000000040" + // ids offset
			"00000000000000000000000000000000000000000000000000000000000000a0" + // values offset (160 bytes)
			"0000000000000000000000000000000000000000000000000000000000000002" + // ids length = 2
			"0000000000000000000000000000000000000000000000000000000000000001" + // id[0] = 1
			"0000000000000000000000000000000000000000000000000000000000000002" + // id[1] = 2
			"0000000000000000000000000000000000000000000000000000000000000002" + // values length = 2
			"0000000000000000000000000000000000000000000000000000000000000064" + // value[0] = 100
			"00000000000000000000000000000000000000000000000000000000000000c8" // value[1] = 200

	ids, values := parseTransferBatchData(data)
	require.Len(t, ids, 2)
	require.Len(t, values, 2)
	assert.Equal(t, "1", ids[0])
	assert.Equal(t, "2", ids[1])
	assert.Equal(t, "100", values[0])
	assert.Equal(t, "200", values[1])
}

func TestParseTransferBatchData_TooShort(t *testing.T) {
	ids, values := parseTransferBatchData("abcd")
	assert.Nil(t, ids)
	assert.Nil(t, values)
}

// ---------------------------------------------------------------------------
// rpcURL test
// ---------------------------------------------------------------------------

func TestRPCSimulator_rpcURL(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: "http://localhost:8545/evm",
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	rs := sim.(*rpcSimulator)
	url := rs.rpcURL("1")
	assert.Equal(t, "http://localhost:8545/evm/1", url)
}

func TestRPCSimulator_rpcURL_TrailingSlash(t *testing.T) {
	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: "http://localhost:8545/",
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	rs := sim.(*rpcSimulator)
	url := rs.rpcURL("137")
	assert.Equal(t, "http://localhost:8545/137", url)
}

// ---------------------------------------------------------------------------
// callSimulateV1 with Auth header
// ---------------------------------------------------------------------------

func TestCallSimulateV1_WithAuthHeader(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		RPCGatewayKey: "my-secret-key",
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-secret-key", authHeader)
}

func TestCallSimulateV1_NoAuthHeader(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.NoError(t, err)
	assert.Empty(t, authHeader)
}

// ---------------------------------------------------------------------------
// context cancellation test
// ---------------------------------------------------------------------------

func TestSimulate_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = sim.Simulate(ctx, &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ComputeBalanceChanges additional test coverage
// ---------------------------------------------------------------------------

func TestComputeBalanceChanges_ERC1155Outflow(t *testing.T) {
	signer := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	events := []SimEvent{
		{
			Address:  "0x1234567890abcdef1234567890abcdef12345678",
			Event:    "TransferSingle",
			Standard: "erc1155",
			Args: map[string]string{
				"from":  signer,
				"to":    "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
				"id":    "99",
				"value": "10",
			},
		},
	}

	changes := ComputeBalanceChanges(events, signer, "", "")
	require.Len(t, changes, 1)
	assert.Equal(t, "erc1155", changes[0].Standard)
	assert.Equal(t, "outflow", changes[0].Direction)
	require.NotNil(t, changes[0].TokenID)
	assert.Equal(t, big.NewInt(99), changes[0].TokenID)
}

func TestComputeBalanceChanges_NativeTransferZeroAmount(t *testing.T) {
	// Native value "0" should not produce changes
	changes := ComputeBalanceChanges(nil, "0xabc", "", "0")
	assert.Empty(t, changes)

	// Native value "0x0" should not produce changes
	changes = ComputeBalanceChanges(nil, "0xabc", "", "0x0")
	assert.Empty(t, changes)

	// Empty string should not produce changes
	changes = ComputeBalanceChanges(nil, "0xabc", "", "")
	assert.Empty(t, changes)
}

func TestComputeBalanceChanges_NonEventERC1155(t *testing.T) {
	// processERC1155Event should skip non-TransferSingle/TransferBatch events
	signer := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	events := []SimEvent{
		{
			Address:  "0x1234567890abcdef1234567890abcdef12345678",
			Event:    "Approval",
			Standard: "erc1155",
			Args: map[string]string{
				"from":  signer,
				"to":    "0xdead",
				"id":    "1",
				"value": "1",
			},
		},
	}
	changes := ComputeBalanceChanges(events, signer, "", "")
	assert.Empty(t, changes)
}

// ---------------------------------------------------------------------------
// parseTransferBatchEvent via ParseEvents
// ---------------------------------------------------------------------------

func TestParseEvents_TransferBatch(t *testing.T) {
	logs := []TxLog{
		{
			Address: "0x1234567890abcdef1234567890abcdef12345678",
			Topics: []string{
				transferBatchTopic0,
				"0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // operator
				"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266", // from
				"0x0000000000000000000000005e1f62dac767b0491e3ce72469c217365d5b48cc", // to
			},
			Data: "0x" +
				"0000000000000000000000000000000000000000000000000000000000000040" + // ids offset
				"00000000000000000000000000000000000000000000000000000000000000a0" + // values offset (160 bytes)
				"0000000000000000000000000000000000000000000000000000000000000002" + // ids len=2
				"0000000000000000000000000000000000000000000000000000000000000001" + // id[0]=1
				"0000000000000000000000000000000000000000000000000000000000000002" + // id[1]=2
				"0000000000000000000000000000000000000000000000000000000000000002" + // values len=2
				"0000000000000000000000000000000000000000000000000000000000000064" + // value[0]=100
				"00000000000000000000000000000000000000000000000000000000000000c8", // value[1]=200
		},
	}

	events := ParseEvents(logs)
	require.Len(t, events, 2)
	assert.Equal(t, "TransferBatch", events[0].Event)
	assert.Equal(t, "erc1155", events[0].Standard)
	assert.Equal(t, "1", events[0].Args["id"])
	assert.Equal(t, "100", events[0].Args["value"])
	assert.Equal(t, "2", events[1].Args["id"])
	assert.Equal(t, "200", events[1].Args["value"])
}

// ---------------------------------------------------------------------------
// Bad server / connection error test
// ---------------------------------------------------------------------------

func TestCallSimulateV1_ConnectionRefused(t *testing.T) {
	// Use a non-routable address to trigger connection error fast
	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: "http://127.0.0.1:1",
		Timeout:       100 * time.Millisecond,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.Error(t, err)
	// Should wrap the connection error
	assert.Contains(t, err.Error(), "rpc request failed")
}

// ---------------------------------------------------------------------------
// findStandardForToken tests
// ---------------------------------------------------------------------------

func TestFindStandardForToken(t *testing.T) {
	events := []SimEvent{
		{
			Address:  "0xabc",
			Standard: "erc721",
			Args:     map[string]string{"tokenId": "42"},
		},
		{
			Address:  "0xdef",
			Standard: "erc1155",
			Args:     map[string]string{"id": "99"},
		},
	}

	standard := findStandardForToken(events, "0xabc", "42")
	assert.Equal(t, "erc721", standard)

	standard = findStandardForToken(events, "0xdef", "99")
	assert.Equal(t, "erc1155", standard)

	// Not found - should default to "erc721"
	standard = findStandardForToken(events, "0xnotfound", "1")
	assert.Equal(t, "erc721", standard)
}

// ---------------------------------------------------------------------------
// Redirect prevention test
// ---------------------------------------------------------------------------

func TestRPCSimulator_RedirectDenied(t *testing.T) {
	// Server that redirects
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://malicious.com", http.StatusMovedPermanently)
	}))
	defer redirectSrv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: redirectSrv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	_, err = sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.Error(t, err)
	// The error might say "redirect" or "rpc request failed" depending on timing
	assert.True(t, strings.Contains(err.Error(), "redirect") ||
		strings.Contains(err.Error(), "rpc request failed"))
}

// ---------------------------------------------------------------------------
// SimulateBatch net balance changes
// ---------------------------------------------------------------------------

func TestSimulateBatch_NetBalanceChanges(t *testing.T) {
	// Two identical tokens (USDC) flowing in opposite directions should cancel out
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]},{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	result, err := sim.SimulateBatch(context.Background(), &BatchSimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Transactions: []TxParams{
			{To: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", Value: "0x0"},
			{To: "0x5e1f62dac767b0491e3ce72469c217365d5b48cc", Value: "0x0"},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.Results, 2)
	// Net balance changes will be empty since none of the TXs emit token events
	assert.Empty(t, result.NetBalanceChanges)
}

// ---------------------------------------------------------------------------
// hex.go: trimHexPrefix zero coverage
// ---------------------------------------------------------------------------

func TestTrimHexPrefix_ZeroXPrefix(t *testing.T) {
	assert.Equal(t, "abcd", trimHexPrefix("0xabcd"))
	assert.Equal(t, "abcd", trimHexPrefix("0Xabcd"))
	assert.Equal(t, "abcd", trimHexPrefix("abcd"))
	assert.Equal(t, "", trimHexPrefix(""))
	assert.Equal(t, "0", trimHexPrefix("0"))
}

// ---------------------------------------------------------------------------
// parseTransferBatchEvent edge cases
// ---------------------------------------------------------------------------

func TestParseTransferBatchEvent_TooFewTopics(t *testing.T) {
	log := TxLog{
		Address: "0xabc",
		Topics:  []string{transferBatchTopic0},
		Data:    "0x",
	}
	events := parseTransferBatchEvent(log)
	assert.Nil(t, events)
}

// ---------------------------------------------------------------------------
// Approval event ERC721 (4 topics)
// ---------------------------------------------------------------------------

func TestParseApprovalEvent_ERC721(t *testing.T) {
	log := TxLog{
		Address: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
		Topics: []string{
			approvalTopic0,
			"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266", // owner
			"0x0000000000000000000000005e1f62dac767b0491e3ce72469c217365d5b48cc", // spender
			"0x0000000000000000000000000000000000000000000000000000000000000064", // tokenId 100
		},
		Data: "0x",
	}

	event := parseApprovalEvent(log)
	require.NotNil(t, event)
	assert.Equal(t, "erc721", event.Standard)
	assert.Equal(t, "100", event.Args["tokenId"])
}

// ---------------------------------------------------------------------------
// ParseEvents: log with no topics
// ---------------------------------------------------------------------------

func TestParseEvents_LogWithNoTopics(t *testing.T) {
	logs := []TxLog{
		{
			Address: "0xabc",
			Topics:  []string{},
			Data:    "0x",
		},
	}
	events := ParseEvents(logs)
	assert.Empty(t, events)
}

// ---------------------------------------------------------------------------
// parseTransferSingleEvent: too few topics
// ---------------------------------------------------------------------------

func TestParseTransferSingleEvent_TooFewTopics(t *testing.T) {
	log := TxLog{
		Address: "0xabc",
		Topics:  []string{transferSingleTopic0},
		Data:    "0x",
	}
	event := parseTransferSingleEvent(log)
	assert.Nil(t, event)
}

// ---------------------------------------------------------------------------
// parseDepositEvent: too few topics
// ---------------------------------------------------------------------------

func TestParseDepositEvent_TooFewTopics(t *testing.T) {
	log := TxLog{
		Address: "0xabc",
		Topics:  []string{depositTopic0},
		Data:    "0x",
	}
	event := parseDepositEvent(log)
	assert.Nil(t, event)
}

// ---------------------------------------------------------------------------
// parseWithdrawalEvent: too few topics
// ---------------------------------------------------------------------------

func TestParseWithdrawalEvent_TooFewTopics(t *testing.T) {
	log := TxLog{
		Address: "0xabc",
		Topics:  []string{withdrawalTopic0},
		Data:    "0x",
	}
	event := parseWithdrawalEvent(log)
	assert.Nil(t, event)
}

// ---------------------------------------------------------------------------
// parseApprovalEvent: too few topics
// ---------------------------------------------------------------------------

func TestParseApprovalEvent_TooFewTopics(t *testing.T) {
	log := TxLog{
		Address: "0xabc",
		Topics:  []string{approvalTopic0},
		Data:    "0x",
	}
	event := parseApprovalEvent(log)
	assert.Nil(t, event)
}

// ---------------------------------------------------------------------------
// parseApprovalForAllEvent: too few topics
// ---------------------------------------------------------------------------

func TestParseApprovalForAllEvent_TooFewTopics(t *testing.T) {
	log := TxLog{
		Address: "0xabc",
		Topics:  []string{approvalForAllTopic0},
		Data:    "0x",
	}
	event := parseApprovalForAllEvent(log)
	assert.Nil(t, event)
}

// ---------------------------------------------------------------------------
// dataToHexValue: short data
// ---------------------------------------------------------------------------

func TestDataToHexValue_ShortData(t *testing.T) {
	val := dataToHexValue("0xabc", 5) // wordIndex 5, well past data length
	assert.Equal(t, "0", val)
}

// ---------------------------------------------------------------------------
// parseUint256Array: short data
// ---------------------------------------------------------------------------

func TestParseUint256Array_ShortData(t *testing.T) {
	result := parseUint256Array("0xabc", 100)
	assert.Nil(t, result)
}

func TestParseUint256Array_Truncated(t *testing.T) {
	// offset past the end of the data
	result := parseUint256Array("abcd", 100)
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// DetectApproval: non-parsable value
// ---------------------------------------------------------------------------

func TestDetectApproval_NonParsableValue(t *testing.T) {
	events := []SimEvent{
		{
			Event: "Approval",
			Args:  map[string]string{"owner": "0xabc", "value": "not-a-number", "spender": "0xdef"},
		},
	}
	result := DetectApproval(context.Background(), events, nil, "", nil)
	assert.True(t, result, "unparseable value should be treated as suspicious")
}

// ---------------------------------------------------------------------------
// approve file
// ---------------------------------------------------------------------------

func TestDetectApproval_ApprovalForAll(t *testing.T) {
	events := []SimEvent{
		{
			Event: "ApprovalForAll",
			Standard: "erc721",
			Args:  map[string]string{"owner": "0xabc"},
		},
	}
	result := DetectApproval(context.Background(), events, nil, "", nil)
	assert.True(t, result, "ApprovalForAll should always be detected")
}

func TestDetectApproval_ZeroValue(t *testing.T) {
	events := []SimEvent{
		{
			Event: "Approval",
			Args:  map[string]string{"owner": "0xabc", "value": "0"},
		},
	}
	result := DetectApproval(context.Background(), events, nil, "", nil)
	assert.False(t, result, "zero-value approval should be skipped")
}

func TestDetectApproval_EmptyValue(t *testing.T) {
	events := []SimEvent{
		{
			Event: "Approval",
			Args:  map[string]string{"owner": "0xabc", "value": ""},
		},
	}
	result := DetectApproval(context.Background(), events, nil, "", nil)
	assert.False(t, result, "empty-value approval should be skipped")
}

func TestDetectApproval_ApprovalForAllEmptyValue(t *testing.T) {
	// ApprovalForAll with empty value: should still be detected
	events := []SimEvent{
		{
			Event: "ApprovalForAll",
			Standard: "erc721",
			Args:  map[string]string{"owner": "0xabc", "value": ""},
		},
	}
	result := DetectApproval(context.Background(), events, nil, "", nil)
	assert.True(t, result, "ApprovalForAll should always be detected")
}

// ---------------------------------------------------------------------------
// DetectDangerousStateChanges: no topics
// ---------------------------------------------------------------------------

func TestDetectDangerousStateChanges_NoTopics(t *testing.T) {
	logs := []TxLog{
		{Topics: []string{}},
	}
	reason := DetectDangerousStateChanges(logs, nil)
	assert.Empty(t, reason)
}

// ---------------------------------------------------------------------------
// Notice: SSRF prevention test
// ---------------------------------------------------------------------------

func TestSimulate_RevertWithEmptyReturnData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x0","gasUsed":"0x5208","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	require.NoError(t, err)

	result, err := sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "transaction reverted", result.RevertReason)
}
