package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
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
