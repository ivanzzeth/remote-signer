// Package evm — rpc_proxy.go is the JSON-RPC proxy the browser
// extension's EIP1193Provider talks to. Centralises chain RPC
// configuration daemon-side so no client (popup, dApp, SDK in
// Node) needs to hold its own list of public endpoints.
//
// Threat model: any authenticated key may proxy through, but the
// method allowlist (evm.WalletProxyAllowedMethods) excludes every
// sign / write-with-key path — those go through /api/v1/evm/sign
// where the rule engine + budget tracking apply. The upstream
// transport reuses the SSRF-resistant RPCProvider (TLS-pinned,
// no redirects, 5s timeout, per-process rate limit + circuit
// breaker), so a compromised key can't turn the daemon into an
// open RPC relay.

package evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// RPCProxyBackend is the minimal interface RPCProxyHandler depends
// on — kept narrow so handler tests can swap in a fake without
// touching the real RPCProvider's rate-limiter / circuit-breaker.
// The real implementation is *evmchain.RPCProvider.
type RPCProxyBackend interface {
	DoWalletProxyRPC(
		ctx context.Context, chainID, method string, params []interface{},
	) (json.RawMessage, error)
}

// TransactionRecorder is the slice of TransactionService the proxy
// needs after observing an eth_sendRawTransaction. Kept narrow so
// the proxy doesn't pull the whole service interface (poll, dropped
// detection, etc.) into its dependency graph — those concerns live
// in the background poller, not on the hot request path.
type TransactionRecorder interface {
	RecordBroadcast(ctx context.Context, chainID, signedTxHex string) (*types.Transaction, error)
}

// RPCProxyHandler implements POST /api/v1/evm/rpc/{chainID}.
type RPCProxyHandler struct {
	backend  RPCProxyBackend
	recorder TransactionRecorder // optional — nil disables tx tracking
	logger   *slog.Logger
}

// NewRPCProxyHandler validates dependencies and returns a ready-to-mount handler.
// `recorder` may be nil — installations without a TransactionService
// just lose the per-broadcast audit row; the proxy itself still works.
func NewRPCProxyHandler(
	backend RPCProxyBackend,
	recorder TransactionRecorder,
	logger *slog.Logger,
) (*RPCProxyHandler, error) {
	if backend == nil {
		return nil, errors.New("rpc backend is required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	return &RPCProxyHandler{backend: backend, recorder: recorder, logger: logger}, nil
}

// Compile-time guard: the real RPCProvider satisfies the interface.
var _ RPCProxyBackend = (*evmchain.RPCProvider)(nil)

// jsonRPCBody is the inbound JSON-RPC envelope shape. We tolerate a
// missing id (dApps that fire-and-forget read calls don't always
// supply one) but round-trip whatever they sent if they did.
type jsonRPCBody struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  []interface{}   `json:"params"`
}

// jsonRPCEnvelope is the outbound shape — either Result or Error
// is set, mirroring the upstream's contract so the dApp side parses
// it exactly like a direct chain-RPC response.
type jsonRPCEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServeHTTP handles a single proxy call. Path: /api/v1/evm/rpc/{chainID}.
//
// JSON-RPC 2.0 convention: every well-formed request returns HTTP
// 200 with a `{jsonrpc, id, result | error}` envelope. Real chain
// nodes (geth, anvil, alchemy, ankr) behave this way — the
// extension SDK's HttpTransport assumes daemon-flat error shapes
// (`{error: "msg"}`), so if we return HTTP 4xx here it'd flatten
// our nested JSON-RPC error to "[object Object]" and the dApp would
// see a useless message. By keeping HTTP status 200 for app-level
// errors (allowlist rejection, upstream failure) we let the SDK
// unpack the standard JSON-RPC envelope and surface a real reason.
//
// Truly HTTP-level errors (wrong method, malformed body) still use
// 4xx — those aren't JSON-RPC responses at all, just transport
// fault.
func (h *RPCProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed: use POST")
		return
	}

	chainID := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/rpc/")
	chainID = strings.TrimSuffix(chainID, "/")
	if chainID == "" || strings.Contains(chainID, "/") {
		h.writeHTTPError(w, http.StatusBadRequest,
			"chain id is required: POST /api/v1/evm/rpc/{chainID}")
		return
	}

	var body jsonRPCBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		// Pre-envelope failure — body isn't JSON-RPC, so we can't
		// reflect an id back. Surface as an HTTP-level 400 so curl
		// users get a sensible signal too.
		h.writeHTTPError(w, http.StatusBadRequest,
			fmt.Sprintf("invalid JSON-RPC body: %s", err))
		return
	}
	if body.Method == "" {
		h.writeRPCError(w, body.ID, -32600, "missing method")
		return
	}
	// Pre-filter sign methods before they even reach RPCProvider so
	// the audit log records a clean rejection. RPCProvider's check
	// inside DoWalletProxyRPC is the defence-in-depth second guard.
	// -32601 is the JSON-RPC standard "method not found" code.
	if !evmchain.WalletProxyAllowedMethods[body.Method] {
		h.logger.Warn("wallet rpc proxy: method blocked",
			slog.String("method", body.Method),
			slog.String("chain_id", chainID))
		h.writeRPCError(w, body.ID, -32601,
			fmt.Sprintf("method %q is not allowed via the wallet proxy", body.Method))
		return
	}

	result, err := h.backend.DoWalletProxyRPC(r.Context(), chainID, body.Method, body.Params)
	if err != nil {
		h.logger.Warn("wallet rpc proxy: upstream failed",
			slog.String("method", body.Method),
			slog.String("chain_id", chainID),
			slog.String("error", err.Error()))
		// -32603 is the JSON-RPC standard "internal error" code —
		// the right slot for upstream/transport failures the caller
		// can't directly fix.
		h.writeRPCError(w, body.ID, -32603, err.Error())
		return
	}

	// After a successful broadcast, hand the signed payload to the
	// TransactionService so it can decode, link to the originating
	// sign_request, and start tracking on-chain status. Strictly
	// best-effort: the upstream has already accepted the tx, the
	// caller gets the success envelope regardless of whether we can
	// persist the audit row. Background context — the request
	// context is about to be cancelled when we return.
	if body.Method == "eth_sendRawTransaction" && h.recorder != nil {
		h.recordBroadcastAsync(chainID, body.Params)
	}

	h.writeJSON(w, http.StatusOK, jsonRPCEnvelope{
		JSONRPC: "2.0",
		ID:      body.ID,
		Result:  result,
	})
}

// recordBroadcastAsync hands the signed-tx hex to the recorder
// outside the request goroutine — the upstream broadcast already
// succeeded and the dApp's response shouldn't wait on our audit
// path. Param-shape failures (missing arg, non-string) get logged
// but never bubble to the caller.
func (h *RPCProxyHandler) recordBroadcastAsync(chainID string, params []interface{}) {
	if len(params) == 0 {
		h.logger.Warn("wallet rpc proxy: eth_sendRawTransaction with no params")
		return
	}
	signedHex, ok := params[0].(string)
	if !ok || signedHex == "" {
		h.logger.Warn("wallet rpc proxy: eth_sendRawTransaction first param not a hex string")
		return
	}
	go func() {
		// context.Background — the request ctx is about to be
		// cancelled. We deliberately don't tie this DB write to the
		// dApp's connection lifecycle.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := h.recorder.RecordBroadcast(ctx, chainID, signedHex); err != nil {
			h.logger.Warn("wallet rpc proxy: record broadcast failed",
				slog.String("chain_id", chainID),
				slog.String("error", err.Error()))
		}
	}()
}

// writeRPCError emits a JSON-RPC error envelope at HTTP 200 — see
// ServeHTTP's docstring for why app-level errors don't carry HTTP
// status. `id` is round-tripped from the request when known, omitted
// otherwise (pre-parse failures take the writeHTTPError path instead).
func (h *RPCProxyHandler) writeRPCError(
	w http.ResponseWriter, id json.RawMessage, code int, msg string,
) {
	h.writeJSON(w, http.StatusOK, jsonRPCEnvelope{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: msg},
	})
}

// writeHTTPError emits a daemon-flat `{"error":"..."}` body matching
// the SDK transport's error contract for genuine transport faults
// (wrong HTTP method, malformed body) — these aren't JSON-RPC at
// all, so use the standard daemon error shape.
func (h *RPCProxyHandler) writeHTTPError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *RPCProxyHandler) writeJSON(w http.ResponseWriter, status int, body jsonRPCEnvelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
