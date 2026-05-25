//go:build integration

package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func newTxServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Transaction{}, &types.SignRequest{}))
	return db
}

func txServiceLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// signLegacyTx produces a deterministic EIP-155 legacy transaction
// signed with a throwaway secp256k1 key. Lets the broadcast-record
// path exercise real RLP decode + sender recovery without a daemon
// roundtrip — the chain id arg is what ends up in the EIP-155 v.
func signLegacyTx(t *testing.T, chainID *big.Int) (signedHex string, expectedFrom common.Address, expectedHash common.Hash) {
	t.Helper()
	priv, err := crypto.GenerateKey()
	require.NoError(t, err)
	expectedFrom = crypto.PubkeyToAddress(priv.PublicKey)
	tx := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21_000,
		To:       &common.Address{0xde, 0xad},
		Value:    big.NewInt(1),
	})
	signer := gethtypes.NewEIP155Signer(chainID)
	signedTx, err := gethtypes.SignTx(tx, signer, priv)
	require.NoError(t, err)
	raw, err := signedTx.MarshalBinary()
	require.NoError(t, err)
	return "0x" + hex.EncodeToString(raw), expectedFrom, signedTx.Hash()
}

func TestTransactionService_RecordBroadcast_DecodesHashAndSender(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	signedHex, expectedFrom, expectedHash := signLegacyTx(t, big.NewInt(56))

	row, err := svc.RecordBroadcast(context.Background(), "56", signedHex)
	require.NoError(t, err)
	assert.Equal(t, "56", row.ChainID)
	// Hash + sender recovered from the RLP — proves the proxy can
	// tell operators which tx hash the dApp's broadcast resolved to
	// without having to trust the upstream's response.
	assert.Equal(t, expectedHash.Hex(), "0x"+row.TxHash[2:])
	assert.Equal(t, expectedFrom.Hex(), row.FromAddress)
	assert.Equal(t, types.TxStatusBroadcasted, row.Status)

	// Lookup by hash round-trips identically.
	got, err := txRepo.GetByHash(context.Background(), "56", row.TxHash)
	require.NoError(t, err)
	assert.Equal(t, row.ID, got.ID)
}

func TestTransactionService_RecordBroadcast_LinksSignRequestByPayload(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	// Seed a completed sign request whose SignedData matches the
	// payload we'll broadcast. The proxy's job: link tx ↔ request.
	signedHex, _, _ := signLegacyTx(t, big.NewInt(1))
	raw, err := hex.DecodeString(signedHex[2:])
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, reqRepo.Create(context.Background(), &types.SignRequest{
		ID:         "req-broadcast",
		ChainType:  types.ChainTypeEVM,
		ChainID:    "1",
		SignType:   "transaction",
		Status:     types.StatusCompleted,
		SignedData: raw,
		CreatedAt:  now,
		UpdatedAt:  now,
	}))

	row, err := svc.RecordBroadcast(context.Background(), "1", signedHex)
	require.NoError(t, err)
	assert.Equal(t, "req-broadcast", row.SignRequestID)

	// Back-ref on sign_request.transaction_id is set so a "what
	// happened to this request" query is one read away.
	r, err := reqRepo.Get(context.Background(), "req-broadcast")
	require.NoError(t, err)
	require.NotNil(t, r.TransactionID)
	assert.Equal(t, row.ID, *r.TransactionID)
}

func TestTransactionService_RecordBroadcast_NoMatchingSignRequest(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	// Third-party caller hits the proxy with bytes the daemon
	// didn't sign — record the tx but leave SignRequestID empty.
	// Pre-implementation this path would have silently dropped the
	// row; the test pins the "store anyway" behavior.
	signedHex, _, _ := signLegacyTx(t, big.NewInt(1))
	row, err := svc.RecordBroadcast(context.Background(), "1", signedHex)
	require.NoError(t, err)
	assert.Equal(t, "", row.SignRequestID)
	assert.Equal(t, types.TxStatusBroadcasted, row.Status)
}

func TestTransactionService_RecordBroadcast_BadRLPRecordsSparse(t *testing.T) {
	// A garbage payload should still leave an audit row so the
	// operator can see "the proxy did broadcast something
	// undecodable" rather than the call disappearing into the void.
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	row, err := svc.RecordBroadcast(context.Background(), "1", "0xdeadbeef")
	require.NoError(t, err)
	assert.Equal(t, types.TxStatusBroadcasted, row.Status)
	assert.Contains(t, row.ErrorMessage, "RLP-decode")
}

func TestTransactionService_PollPending_NoRPC(t *testing.T) {
	// Service constructed without an rpc provider can still record,
	// but PollPending should fail cleanly (not panic) — operators
	// running record-only configs need a usable error to telemetry.
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)
	_, _, err = svc.PollPending(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpc provider")
}

func TestTransactionService_RecordBroadcast_ChainMismatchStillRecords(t *testing.T) {
	// This is exactly the BSC USDT regression: signed for chain 1
	// but the URL path says 56. Record the row anyway — the row
	// is the audit trail. The warning gets logged but the call
	// shouldn't fail (the bytes already went out to upstream).
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	signedHex, _, _ := signLegacyTx(t, big.NewInt(1))
	row, err := svc.RecordBroadcast(context.Background(), "56", signedHex)
	require.NoError(t, err)
	assert.Equal(t, "56", row.ChainID) // we record what the URL said
}

func TestTransactionService_RecordBroadcast_InvalidHex(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	_, err = svc.RecordBroadcast(context.Background(), "1", "zzz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestTransactionService_NewTransactionService_Errors(t *testing.T) {
	t.Run("nil repo", func(t *testing.T) {
		_, err := NewTransactionService(nil, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "transaction repository is required")
	})

	t.Run("nil request repo", func(t *testing.T) {
		db := newTxServiceTestDB(t)
		txRepo, err := storage.NewGormTransactionRepository(db)
		require.NoError(t, err)
		_, err = NewTransactionService(txRepo, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request repository is required")
	})

	t.Run("nil logger", func(t *testing.T) {
		db := newTxServiceTestDB(t)
		txRepo, err := storage.NewGormTransactionRepository(db)
		require.NoError(t, err)
		reqRepo, err := storage.NewGormRequestRepository(db)
		require.NoError(t, err)
		_, err = NewTransactionService(txRepo, reqRepo, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// --- PollPending / Run tests ---

// jsonRPCServer is a lightweight httptest server that handles
// eth_getTransactionReceipt calls. The handler func receives the
// raw JSON-RPC request body and returns a JSON-RPC response body.
func newRPCTestServer(handler func(body []byte) ([]byte, error)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", 500)
			return
		}
		resp, err := handler(body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}))
}

// rpcProviderFromServer creates an RPCProvider pointed at the test
// server. The baseURL is the server URL without path; the RPCProvider
// appends /<chainID>/api_key/<key> internally.
func rpcProviderFromServer(t *testing.T, srv *httptest.Server) *evmchain.RPCProvider {
	t.Helper()
	p, err := evmchain.NewRPCProvider(srv.URL, "test-api-key")
	require.NoError(t, err)
	return p
}

func jsonRPCRespResult(result string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","result":%s,"id":1}`, result))
}

func jsonRPCRespError(code int, msg string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","error":{"code":%d,"message":"%s"},"id":1}`, code, msg))
}

func TestTransactionService_PollPending_WithRPC(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`{
			"blockNumber": "0x123",
			"status": "0x1",
			"gasUsed": "0x5208"
		}`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	now := time.Now()
	tx := &types.Transaction{
		ID:            "tx-poll-1",
		ChainID:       "1",
		TxHash:        "0xabc123",
		FromAddress:   "0xfrom",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: now,
		LastCheckedAt: &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, txRepo.Create(context.Background(), tx))

	mined, dropped, err := svc.PollPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, mined)
	assert.Equal(t, 0, dropped)
}

func TestTransactionService_PollPending_ReceiptNull_DroppedAfterGrace(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`null`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)
	svc.WithGracePeriod(0)

	now := time.Now()
	tx := &types.Transaction{
		ID:            "tx-poll-null",
		ChainID:       "1",
		TxHash:        "0xdef456",
		FromAddress:   "0xfrom",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: now,
		LastCheckedAt: &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, txRepo.Create(context.Background(), tx))

	mined, dropped, err := svc.PollPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, mined)
	assert.Equal(t, 1, dropped)
}

func TestTransactionService_PollPending_ReceiptNull_StillWithinGrace(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`null`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)
	svc.WithGracePeriod(24 * time.Hour)

	now := time.Now()
	tx := &types.Transaction{
		ID:            "tx-poll-grace",
		ChainID:       "1",
		TxHash:        "0xgrace789",
		FromAddress:   "0xfrom",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: now,
		LastCheckedAt: &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, txRepo.Create(context.Background(), tx))

	mined, dropped, err := svc.PollPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, mined)
	assert.Equal(t, 0, dropped)
}

func TestTransactionService_PollPending_ReceiptStatusZero(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`{
			"blockNumber": "0x456",
			"status": "0x0",
			"gasUsed": "0x5208"
		}`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	now := time.Now()
	tx := &types.Transaction{
		ID:            "tx-poll-fail",
		ChainID:       "1",
		TxHash:        "0xrevert",
		FromAddress:   "0xfrom",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: now,
		LastCheckedAt: &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, txRepo.Create(context.Background(), tx))

	mined, dropped, err := svc.PollPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, mined)
	assert.Equal(t, 0, dropped)

	got, err := txRepo.Get(context.Background(), "tx-poll-fail")
	require.NoError(t, err)
	assert.Equal(t, types.TxStatusMined, got.Status)
	assert.NotNil(t, got.ReceiptStatus)
	assert.Equal(t, uint8(0), *got.ReceiptStatus)
}

func TestTransactionService_PollPending_ReceiptStatusDecString(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`{"blockNumber": "0x789", "status": "1"}`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	now := time.Now()
	tx := &types.Transaction{
		ID:            "tx-poll-decimal",
		ChainID:       "1",
		TxHash:        "0xdec1",
		FromAddress:   "0xfrom",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: now,
		LastCheckedAt: &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, txRepo.Create(context.Background(), tx))

	mined, _, err := svc.PollPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, mined)
	got, err := txRepo.Get(context.Background(), "tx-poll-decimal")
	require.NoError(t, err)
	assert.NotNil(t, got.ReceiptStatus)
	assert.Equal(t, uint8(1), *got.ReceiptStatus)
}

func TestTransactionService_PollPending_BadReceiptJSON(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`"not-an-object"`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	now := time.Now()
	tx := &types.Transaction{
		ID:            "tx-poll-badj",
		ChainID:       "1",
		TxHash:        "0xbadj",
		FromAddress:   "0xfrom",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: now,
		LastCheckedAt: &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, txRepo.Create(context.Background(), tx))

	mined, dropped, err := svc.PollPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, mined)
	assert.Equal(t, 0, dropped)
}

func TestTransactionService_PollPending_RPCError(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespError(-32000, "execution reverted"), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	now := time.Now()
	tx := &types.Transaction{
		ID:            "tx-poll-rpcerr",
		ChainID:       "1",
		TxHash:        "0xrpcerr",
		FromAddress:   "0xfrom",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: now,
		LastCheckedAt: &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, txRepo.Create(context.Background(), tx))

	mined, dropped, err := svc.PollPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, mined)
	assert.Equal(t, 0, dropped)
}

func TestTransactionService_PollPending_EmptyPendingList(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`{"blockNumber": "0x1", "status": "0x1"}`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	mined, dropped, err := svc.PollPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, mined)
	assert.Equal(t, 0, dropped)
}

func TestTransactionService_Run_NoRPC(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	svc.Run(ctx, 0)
	cancel()
}

func TestTransactionService_Run_StopsOnCancel(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`{"blockNumber": "0x1", "status": "0x1"}`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.Run(ctx, 10*time.Millisecond)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}

func TestTransactionService_Run_DefaultInterval(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	srv := newRPCTestServer(func(body []byte) ([]byte, error) {
		return jsonRPCRespResult(`{"blockNumber": "0x1", "status": "0x1"}`), nil
	})
	defer srv.Close()

	rpc := rpcProviderFromServer(t, srv)
	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.Run(ctx, -1)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
}

func TestTransactionService_WithGracePeriod(t *testing.T) {
	db := newTxServiceTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	custom := 5 * time.Minute
	assert.Equal(t, svc, svc.WithGracePeriod(custom))
	assert.Equal(t, custom, svc.gracePeriod)
}
