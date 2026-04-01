package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/simulation"
)

// --- Mock AnvilForkManager ---

type mockAnvilForkManager struct {
	simulateFn      func(ctx context.Context, req *simulation.SimulationRequest) (*simulation.SimulationResult, error)
	simulateBatchFn func(ctx context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error)
	statusFn        func(ctx context.Context) *simulation.ManagerStatus
}

func (m *mockAnvilForkManager) Simulate(ctx context.Context, req *simulation.SimulationRequest) (*simulation.SimulationResult, error) {
	if m.simulateFn != nil {
		return m.simulateFn(ctx, req)
	}
	return &simulation.SimulationResult{Success: true, GasUsed: 21000}, nil
}

func (m *mockAnvilForkManager) SimulateBatch(ctx context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
	if m.simulateBatchFn != nil {
		return m.simulateBatchFn(ctx, req)
	}
	return &simulation.BatchSimulationResult{
		Results: []simulation.SimulationResult{{Success: true, GasUsed: 21000}},
	}, nil
}

func (m *mockAnvilForkManager) SyncIfDirty(_ context.Context, _ string) error { return nil }
func (m *mockAnvilForkManager) MarkDirty(_ string)                            {}
func (m *mockAnvilForkManager) Status(ctx context.Context) *simulation.ManagerStatus {
	if m.statusFn != nil {
		return m.statusFn(ctx)
	}
	return &simulation.ManagerStatus{}
}
func (m *mockAnvilForkManager) Close() error { return nil }

// --- Helpers ---

func doSimulateRequest(t *testing.T, handler http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(data)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func newTestSimulateHandler(t *testing.T, mgr simulation.AnvilForkManager) *SimulateHandler {
	t.Helper()
	h, err := NewSimulateHandler(mgr, slog.Default())
	require.NoError(t, err)
	return h
}

// --- Constructor tests ---

func TestNewSimulateHandler(t *testing.T) {
	t.Run("nil_simulator_returns_error", func(t *testing.T) {
		_, err := NewSimulateHandler(nil, slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "simulator is required")
	})

	t.Run("nil_logger_returns_error", func(t *testing.T) {
		_, err := NewSimulateHandler(&mockAnvilForkManager{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("valid_args", func(t *testing.T) {
		h, err := NewSimulateHandler(&mockAnvilForkManager{}, slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- ServeHTTP (single simulate) tests ---

func TestSimulateHandler_MethodNotAllowed(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	rec := doSimulateRequest(t, h, http.MethodGet, "/api/v1/evm/simulate", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestSimulateHandler_InvalidBody(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/simulate", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSimulateHandler_MissingChainID(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	body := SimulateRequest{From: "0x1111111111111111111111111111111111111111", To: "0x2222222222222222222222222222222222222222"}
	rec := doSimulateRequest(t, h, http.MethodPost, "/api/v1/evm/simulate", body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "chain_id")
}

func TestSimulateHandler_InvalidChainID(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	body := SimulateRequest{ChainID: "abc", From: "0x1111111111111111111111111111111111111111", To: "0x2222222222222222222222222222222222222222"}
	rec := doSimulateRequest(t, h, http.MethodPost, "/api/v1/evm/simulate", body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSimulateHandler_MissingFrom(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	body := SimulateRequest{ChainID: "1", To: "0x2222222222222222222222222222222222222222"}
	rec := doSimulateRequest(t, h, http.MethodPost, "/api/v1/evm/simulate", body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "from")
}

func TestSimulateHandler_InvalidFrom(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	body := SimulateRequest{ChainID: "1", From: "not-an-address", To: "0x2222222222222222222222222222222222222222"}
	rec := doSimulateRequest(t, h, http.MethodPost, "/api/v1/evm/simulate", body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSimulateHandler_MissingTo(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	body := SimulateRequest{ChainID: "1", From: "0x1111111111111111111111111111111111111111"}
	rec := doSimulateRequest(t, h, http.MethodPost, "/api/v1/evm/simulate", body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "to")
}

func TestSimulateHandler_InvalidData(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	body := SimulateRequest{
		ChainID: "1",
		From:    "0x1111111111111111111111111111111111111111",
		To:      "0x2222222222222222222222222222222222222222",
		Data:    "not-hex",
	}
	rec := doSimulateRequest(t, h, http.MethodPost, "/api/v1/evm/simulate", body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "data")
}

func TestSimulateHandler_Success(t *testing.T) {
	mgr := &mockAnvilForkManager{
		simulateFn: func(_ context.Context, req *simulation.SimulationRequest) (*simulation.SimulationResult, error) {
			assert.Equal(t, "1", req.ChainID)
			assert.Equal(t, "0x1111111111111111111111111111111111111111", req.From)
			return &simulation.SimulationResult{
				Success: true,
				GasUsed: 42000,
			}, nil
		},
	}
	h := newTestSimulateHandler(t, mgr)
	body := SimulateRequest{
		ChainID: "1",
		From:    "0x1111111111111111111111111111111111111111",
		To:      "0x2222222222222222222222222222222222222222",
		Value:   "1000",
	}
	rec := doSimulateRequest(t, h, http.MethodPost, "/api/v1/evm/simulate", body)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp SimulateResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.True(t, resp.Success)
	assert.Equal(t, uint64(42000), resp.GasUsed)
}

func TestSimulateHandler_SimulatorError(t *testing.T) {
	mgr := &mockAnvilForkManager{
		simulateFn: func(_ context.Context, _ *simulation.SimulationRequest) (*simulation.SimulationResult, error) {
			return nil, fmt.Errorf("anvil fork crashed")
		},
	}
	h := newTestSimulateHandler(t, mgr)
	body := SimulateRequest{
		ChainID: "1",
		From:    "0x1111111111111111111111111111111111111111",
		To:      "0x2222222222222222222222222222222222222222",
	}
	rec := doSimulateRequest(t, h, http.MethodPost, "/api/v1/evm/simulate", body)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "simulation failed")
}

// --- ServeBatchHTTP tests ---

func TestSimulateHandler_BatchSuccess(t *testing.T) {
	mgr := &mockAnvilForkManager{
		simulateBatchFn: func(_ context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
			assert.Equal(t, 2, len(req.Transactions))
			return &simulation.BatchSimulationResult{
				Results: []simulation.SimulationResult{
					{Success: true, GasUsed: 21000},
					{Success: true, GasUsed: 50000},
				},
			}, nil
		},
	}
	h := newTestSimulateHandler(t, mgr)
	body := BatchSimulateRequest{
		ChainID: "1",
		From:    "0x1111111111111111111111111111111111111111",
		Transactions: []TxParamsJSON{
			{To: "0x2222222222222222222222222222222222222222", Value: "100"},
			{To: "0x3333333333333333333333333333333333333333", Value: "200"},
		},
	}
	rec := httptest.NewRecorder()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/simulate/batch", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	h.ServeBatchHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BatchSimulateResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, len(resp.Results))
}

func TestSimulateHandler_BatchMethodNotAllowed(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/simulate/batch", nil)
	rec := httptest.NewRecorder()
	h.ServeBatchHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestSimulateHandler_BatchEmptyTransactions(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	body := BatchSimulateRequest{
		ChainID:      "1",
		From:         "0x1111111111111111111111111111111111111111",
		Transactions: []TxParamsJSON{},
	}
	rec := httptest.NewRecorder()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/simulate/batch", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	h.ServeBatchHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSimulateHandler_BatchExceedsMax(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	txs := make([]TxParamsJSON, 21) // exceeds maxBatchSimulateSize=20
	for i := range txs {
		txs[i] = TxParamsJSON{To: "0x2222222222222222222222222222222222222222"}
	}
	body := BatchSimulateRequest{
		ChainID:      "1",
		From:         "0x1111111111111111111111111111111111111111",
		Transactions: txs,
	}
	rec := httptest.NewRecorder()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/simulate/batch", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	h.ServeBatchHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "exceeds maximum")
}

func TestSimulateHandler_BatchInvalidTxTo(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	body := BatchSimulateRequest{
		ChainID: "1",
		From:    "0x1111111111111111111111111111111111111111",
		Transactions: []TxParamsJSON{
			{To: "bad-address"},
		},
	}
	rec := httptest.NewRecorder()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/simulate/batch", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	h.ServeBatchHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSimulateHandler_BatchSimulatorError(t *testing.T) {
	mgr := &mockAnvilForkManager{
		simulateBatchFn: func(_ context.Context, _ *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
			return nil, fmt.Errorf("batch failed")
		},
	}
	h := newTestSimulateHandler(t, mgr)
	body := BatchSimulateRequest{
		ChainID: "1",
		From:    "0x1111111111111111111111111111111111111111",
		Transactions: []TxParamsJSON{
			{To: "0x2222222222222222222222222222222222222222"},
		},
	}
	rec := httptest.NewRecorder()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/simulate/batch", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	h.ServeBatchHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// --- ServeStatusHTTP tests ---

func TestSimulateHandler_StatusSuccess(t *testing.T) {
	mgr := &mockAnvilForkManager{
		statusFn: func(_ context.Context) *simulation.ManagerStatus {
			return &simulation.ManagerStatus{}
		},
	}
	h := newTestSimulateHandler(t, mgr)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/simulate/status", nil)
	rec := httptest.NewRecorder()
	h.ServeStatusHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSimulateHandler_StatusMethodNotAllowed(t *testing.T) {
	h := newTestSimulateHandler(t, &mockAnvilForkManager{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/simulate/status", nil)
	rec := httptest.NewRecorder()
	h.ServeStatusHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
