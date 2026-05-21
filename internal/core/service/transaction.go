// Package service — transaction.go is the daemon-side authority on
// what happened to a signed transaction after the wallet RPC proxy
// broadcast it.
//
// Two responsibilities:
//
//  1. RecordBroadcast — called by the wallet RPC proxy when the
//     upstream accepts an eth_sendRawTransaction. Decodes the raw
//     payload to extract hash + sender + chain id, tries to match
//     it back to a sign request via SignedData equality, writes a
//     `transactions` row, and updates sign_requests.transaction_id
//     so a query for "what happened to this sign request" is a
//     single join.
//
//  2. PollPending — periodic background sweep that fetches receipts
//     for broadcasted-but-not-mined txs. Moves them to Mined (with
//     block + receipt status + gas used) once the upstream returns
//     a receipt, or to Dropped after the grace period expires
//     without one. The wallet UI reads the resulting status without
//     having to round-trip to the chain itself.

package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// DroppedTxGracePeriod is how long we wait after the broadcast
// before flipping a still-unmined tx to Dropped. Picked at 10 min so
// even a heavily-congested chain (post-NFT-mint mainnet, pre-fork
// BSC) has time to land a tx that paid a reasonable fee; bumped via
// `WithDroppedGracePeriod` if a particular deployment needs longer.
const DroppedTxGracePeriod = 10 * time.Minute

// TransactionService owns broadcast → mined lifecycle bookkeeping.
type TransactionService struct {
	repo        storage.TransactionRepository
	requestRepo storage.RequestRepository
	rpc         *evmchain.RPCProvider
	logger      *slog.Logger
	gracePeriod time.Duration
}

// NewTransactionService validates dependencies and returns a ready service.
// rpc may be nil if the caller is exclusively recording (no polling) —
// the proxy registration site passes nil-tolerant for that case.
func NewTransactionService(
	repo storage.TransactionRepository,
	requestRepo storage.RequestRepository,
	rpc *evmchain.RPCProvider,
	logger *slog.Logger,
) (*TransactionService, error) {
	if repo == nil {
		return nil, fmt.Errorf("transaction repository is required")
	}
	if requestRepo == nil {
		return nil, fmt.Errorf("request repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &TransactionService{
		repo:        repo,
		requestRepo: requestRepo,
		rpc:         rpc,
		logger:      logger,
		gracePeriod: DroppedTxGracePeriod,
	}, nil
}

// WithGracePeriod overrides the default for Dropped detection. Useful
// for tests that need to assert the dropped path without sleeping
// 10 minutes.
func (s *TransactionService) WithGracePeriod(d time.Duration) *TransactionService {
	s.gracePeriod = d
	return s
}

// RecordBroadcast persists a new transactions row keyed by the
// keccak256 hash of the signed RLP and (best-effort) links it back
// to the originating sign request via the SignedData equality match.
//
// `signedTxHex` is the 0x-prefixed bytes the dApp passed to
// eth_sendRawTransaction; `chainIDFromURL` is the path-param chain id
// (lets us cross-check against the chain encoded into the signature's
// v — mismatch is the BSC USDT regression and we surface it loudly
// in the logs).
func (s *TransactionService) RecordBroadcast(
	ctx context.Context,
	chainIDFromURL string,
	signedTxHex string,
) (*types.Transaction, error) {
	raw, err := decodeHexBytes(signedTxHex)
	if err != nil {
		return nil, fmt.Errorf("decode signed tx hex: %w", err)
	}

	var ethTx gethtypes.Transaction
	if err := ethTx.UnmarshalBinary(raw); err != nil {
		// Unmarshal failure means we can't extract hash/sender/chain.
		// We still want to persist *something* so the operator can
		// see "a tx broadcast happened but we couldn't decode it" —
		// fall back to a sparse row keyed by the bytes' hash.
		s.logger.Warn("tx: RLP decode failed; recording sparse row",
			slog.String("chain_id", chainIDFromURL),
			slog.String("error", err.Error()))
		return s.recordSparse(ctx, chainIDFromURL, raw)
	}

	chainIDFromSig := ""
	if ethTx.ChainId() != nil {
		chainIDFromSig = ethTx.ChainId().String()
	}
	// Recover sender. NewLondonSigner subsumes legacy / 1559 / 2930.
	// For very old pre-EIP-155 txs (chain id 0) this still works.
	var fromAddr string
	if cid := ethTx.ChainId(); cid != nil && cid.Sign() > 0 {
		if sender, sErr := gethtypes.Sender(gethtypes.NewLondonSigner(cid), &ethTx); sErr == nil {
			fromAddr = sender.Hex()
		}
	}

	hash := ethTx.Hash().Hex()

	// Chain mismatch surfacing — the BSC USDT regression. We don't
	// reject the record (the tx already went to upstream), but we
	// log loudly so operators see "this is dead on arrival".
	if chainIDFromSig != "" && chainIDFromSig != chainIDFromURL {
		s.logger.Warn("tx: chain id mismatch between proxy URL and signed payload",
			slog.String("url_chain_id", chainIDFromURL),
			slog.String("signed_chain_id", chainIDFromSig),
			slog.String("tx_hash", hash))
	}

	// Link back to the sign request that produced these bytes.
	signRequestID := ""
	if matched, lErr := s.requestRepo.LookupBySignedData(ctx, raw); lErr == nil && matched != nil {
		signRequestID = string(matched.ID)
	}

	row := &types.Transaction{
		ID:            uuid.New().String(),
		SignRequestID: signRequestID,
		ChainID:       chainIDFromURL,
		TxHash:        strings.ToLower(hash),
		FromAddress:   fromAddr,
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: time.Now(),
	}
	if err := s.repo.Create(ctx, row); err != nil {
		return nil, fmt.Errorf("persist transaction: %w", err)
	}

	if signRequestID != "" {
		if err := s.requestRepo.SetTransactionID(ctx, types.SignRequestID(signRequestID), row.ID); err != nil {
			// Non-fatal — the tx row is the canonical record. The
			// back-ref is a query-convenience; loss surfaces as "no
			// tx column on the Requests page" but the tx is still
			// queryable by hash or by /transactions list.
			s.logger.Warn("tx: failed to set sign_request.transaction_id back-ref",
				slog.String("sign_request_id", signRequestID),
				slog.String("transaction_id", row.ID),
				slog.String("error", err.Error()))
		}
	}

	s.logger.Info("tx: recorded broadcast",
		slog.String("id", row.ID),
		slog.String("chain_id", row.ChainID),
		slog.String("tx_hash", row.TxHash),
		slog.String("from", row.FromAddress),
		slog.String("sign_request_id", row.SignRequestID))
	return row, nil
}

// recordSparse persists a tx the proxy saw but couldn't RLP-decode.
// Keeps the operator's audit trail honest ("the proxy did broadcast
// something") without faking a hash we don't actually know — uses
// the raw payload's keccak as a deterministic stand-in id.
func (s *TransactionService) recordSparse(
	ctx context.Context, chainID string, raw []byte,
) (*types.Transaction, error) {
	fallbackHash := strings.ToLower(common.BytesToHash(crypto.Keccak256(raw)).Hex())
	row := &types.Transaction{
		ID:            uuid.New().String(),
		ChainID:       chainID,
		TxHash:        fallbackHash,
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: time.Now(),
		ErrorMessage:  "could not RLP-decode broadcast payload",
	}
	if err := s.repo.Create(ctx, row); err != nil {
		return nil, fmt.Errorf("persist sparse transaction: %w", err)
	}
	return row, nil
}

// PollPending sweeps the broadcasted-but-not-mined queue once.
// Returns counts so the caller can log / surface metrics. Designed
// to be called from a ticker; safe to invoke concurrently because
// the repo update is row-scoped.
func (s *TransactionService) PollPending(ctx context.Context) (
	mined int, dropped int, err error,
) {
	if s.rpc == nil {
		return 0, 0, fmt.Errorf("rpc provider not configured")
	}
	pending, listErr := s.repo.ListPending(ctx, 100)
	if listErr != nil {
		return 0, 0, fmt.Errorf("list pending: %w", listErr)
	}
	now := time.Now()
	for _, tx := range pending {
		raw, fetchErr := s.rpc.GetTransactionReceipt(ctx, tx.ChainID, tx.TxHash)
		tsCopy := now
		tx.LastCheckedAt = &tsCopy
		if fetchErr != nil {
			s.logger.Warn("tx poll: receipt fetch failed",
				slog.String("tx_hash", tx.TxHash),
				slog.String("chain_id", tx.ChainID),
				slog.String("error", fetchErr.Error()))
			_ = s.repo.Update(ctx, tx)
			continue
		}
		// Receipt absent (still in mempool or never accepted). Decide
		// dropped only after the grace period; until then keep polling.
		if isNullReceipt(raw) {
			if now.Sub(tx.BroadcastedAt) > s.gracePeriod {
				tx.Status = types.TxStatusDropped
				tx.ErrorMessage = "no receipt after grace period"
				dropped++
			}
			_ = s.repo.Update(ctx, tx)
			continue
		}
		// Mined — parse the receipt for block + status + gas used.
		var rcpt struct {
			BlockNumber string `json:"blockNumber"`
			Status      string `json:"status"`
			GasUsed     string `json:"gasUsed"`
		}
		if jErr := json.Unmarshal(raw, &rcpt); jErr != nil {
			s.logger.Warn("tx poll: receipt JSON parse failed",
				slog.String("tx_hash", tx.TxHash),
				slog.String("error", jErr.Error()))
			_ = s.repo.Update(ctx, tx)
			continue
		}
		tx.Status = types.TxStatusMined
		if bn, ok := hexToUint64(rcpt.BlockNumber); ok {
			tx.BlockNumber = &bn
		}
		if gu, ok := hexToUint64(rcpt.GasUsed); ok {
			tx.GasUsed = &gu
		}
		st := uint8(0)
		if rcpt.Status == "0x1" || rcpt.Status == "1" {
			st = 1
		}
		tx.ReceiptStatus = &st
		mn := now
		tx.MinedAt = &mn
		_ = s.repo.Update(ctx, tx)
		mined++
	}
	return mined, dropped, nil
}

// --- helpers ---

func decodeHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

func hexToUint64(s string) (uint64, bool) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

// isNullReceipt is true when the RPC returned `null` (tx not yet
// mined). The provider returns the bare RawMessage; we trim
// whitespace so JSON formatting from various upstreams doesn't trip
// the check.
func isNullReceipt(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t == "" || t == "null"
}

