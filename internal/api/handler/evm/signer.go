package evm

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// SignerHandler handles signer management endpoints
type SignerHandler struct {
	signerManager      evm.SignerManager
	accessService      *service.SignerAccessService
	signerRepo         storage.SignerRepository
	walletRepo         storage.WalletRepository
	readOnly           func() bool // when true, block signer creation via API
	maxKeystoresPerKey func() int  // resource limit: max keystores per API key (0 = no limit)
	logger             *slog.Logger
	auditLogger        *audit.AuditLogger // optional: audit logging
}

// TransferOwnershipRequest represents the request to transfer signer ownership.
type TransferOwnershipRequest struct {
	NewOwnerID string `json:"new_owner_id"`
}

// NewSignerHandler creates a new signer handler
func NewSignerHandler(signerManager evm.SignerManager, accessService *service.SignerAccessService, logger *slog.Logger, readOnly func() bool) (*SignerHandler, error) {
	if signerManager == nil {
		return nil, fmt.Errorf("signer manager is required")
	}
	if accessService == nil {
		return nil, fmt.Errorf("access service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SignerHandler{
		signerManager: signerManager,
		accessService: accessService,
		readOnly:      readOnly,
		logger:        logger,
	}, nil
}

// SetSignerRepo sets DB signer inventory repository for response enrichment.
func (h *SignerHandler) SetSignerRepo(repo storage.SignerRepository) {
	h.signerRepo = repo
}

// SetWalletRepo sets wallet repository for signer->wallet aggregation.
func (h *SignerHandler) SetWalletRepo(repo storage.WalletRepository) {
	h.walletRepo = repo
}

// SetAuditLogger sets the audit logger for signer management operations.
func (h *SignerHandler) SetAuditLogger(al *audit.AuditLogger) {
	h.auditLogger = al
}

// SetMaxKeystoresPerKey sets the resource limit for maximum keystores per API key.
func (h *SignerHandler) SetMaxKeystoresPerKey(max func() int) {
	h.maxKeystoresPerKey = max
}

// --- Handler entry points ---
//
// # One exported function per endpoint (proposal S4, copying S3's and the
// HD-wallet step's shape)
//
// These eleven replace ServeHTTP and HandleSignerAction, which took
// r.URL.Path apart with TrimPrefix/SplitN and fanned out into them. The
// registration that used to hide them behind one method-less prefix plus six
// method-scoped patterns is internal/api/module_signers.go, and it now names
// each one.
//
// ⛔ SignerHandler is deliberately no longer an http.Handler, and there is no
// HandleSignerAction any more. Both were ways of handing the whole signer
// surface to one pattern, and that is the property being removed:
//
//	`/api/v1/evm/signers/` was registered with no method, so it matched every
//	verb. Go's ServeMux answers 405 only when a pattern matches the path and
//	*no* pattern matches the method — with a method-less prefix in the table
//	there is always a match, so `GET .../{address}/unlock` and
//	`DELETE .../{address}/approve` reached HandleSignerAction, which read the
//	action out of the path and performed it. That was fixed in 6d30ba1 by an
//	explicit signerActionMethods guard inside the handler; the guard is gone
//	from here because the routes now state the same rule where the mux can
//	enforce it. TestSignerRoutes_StateChangeRequiresPost asserts it through the
//	production patterns, and asserts the manager was never called — refusing
//	after mutating is not refusing.
//
// ⚠️ Every guard the two dispatchers ran before fanning out is still run, in
// the same order and with the same words and status codes — see requireAPIKey
// and signerAddress. Only the dispatch left.

// requireAPIKey is the 401 both dispatchers answered at their top, before they
// looked at the path at all. ⚠️ It is not redundant with the middleware chain:
// a request that reaches a registered route has a key, but these functions are
// also called directly by tests, and several of the callees dereference the key
// without checking it.
func (h *SignerHandler) requireAPIKey(w http.ResponseWriter, r *http.Request) bool {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return false
	}
	return true
}

// signerAddress is requireAPIKey plus the {address} wildcard.
//
// ⚠️ It does NOT validate the address. HandleSignerAction did not either — it
// took whatever segment followed the prefix — and the ownership lookup in each
// callee is what answers 403/404 for an address that does not exist. Adding a
// format check here would turn those into 400 and is a behaviour change this
// step has no business making.
func (h *SignerHandler) signerAddress(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !h.requireAPIKey(w, r) {
		return "", false
	}
	return r.PathValue("address"), true
}

// ListSigners serves GET /api/v1/evm/signers.
func (h *SignerHandler) ListSigners(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.listSigners(w, r)
}

// CreateSigner serves POST /api/v1/evm/signers.
func (h *SignerHandler) CreateSigner(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.createSigner(w, r)
}

// DeleteSigner serves DELETE /api/v1/evm/signers/{address}.
func (h *SignerHandler) DeleteSigner(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleDeleteSigner(w, r, address)
}

// PatchSignerLabels serves PATCH /api/v1/evm/signers/{address}.
func (h *SignerHandler) PatchSignerLabels(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handlePatchSignerLabels(w, r, address)
}

// Unlock serves POST /api/v1/evm/signers/{address}/unlock.
func (h *SignerHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleUnlock(w, r, address)
}

// Lock serves POST /api/v1/evm/signers/{address}/lock.
func (h *SignerHandler) Lock(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleLock(w, r, address)
}

// ApproveSigner serves POST /api/v1/evm/signers/{address}/approve.
func (h *SignerHandler) ApproveSigner(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleApproveSigner(w, r, address)
}

// TransferOwnership serves POST /api/v1/evm/signers/{address}/transfer.
func (h *SignerHandler) TransferOwnership(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleTransferOwnership(w, r, address)
}

// ListAccess serves GET /api/v1/evm/signers/{address}/access.
func (h *SignerHandler) ListAccess(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleListAccess(w, r, address)
}

// GrantAccess serves POST /api/v1/evm/signers/{address}/access.
func (h *SignerHandler) GrantAccess(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleGrantAccess(w, r, address)
}

// RevokeAccess serves DELETE /api/v1/evm/signers/{address}/access/{keyID}.
//
// ⚠️ handleAccess used to answer 400 "api_key_id is required in path" when the
// key id segment was empty, which was only reachable because a prefix pattern
// let `DELETE .../{address}/access` reach a handler at all. A {keyID} wildcard
// does not match an empty segment, so that request now matches no DELETE
// pattern and the mux answers 405 (GET and POST are registered on that path).
// The guard is gone rather than kept as unreachable code.
func (h *SignerHandler) RevokeAccess(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleRevokeAccess(w, r, address, r.PathValue("keyID"))
}

// readOnly reports whether write operations are blocked right now.
//
// It is a function, not a bool, because the setting behind it is runtime
// mutable: settings.SecuritySnapshot is reloaded from the database, and a
// value copied into this struct at construction would freeze at boot. That
// was the actual behaviour until 2026-09-10 — internal/settings/model.go
// promises settings become "effective without a daemon restart", and for this
// one, flipping it in the Web UI changed the database, changed the snapshot,
// and changed nothing else.
//
// nil means "never read-only", which is the permissive direction; the router
// only leaves it nil when there is no settings manager at all (tests).
func (h *SignerHandler) isReadOnly() bool {
	if h.readOnly == nil {
		return false
	}
	return h.readOnly()
}

// maxKeystoresPerKeyValue reads the limit at request time. See Router.liveInt: the setting
// behind it is runtime mutable, so a value captured at construction freezes at
// boot. nil means unset, which these fields already meant as 0.
func (h *SignerHandler) maxKeystoresPerKeyValue() int {
	if h.maxKeystoresPerKey == nil {
		return 0
	}
	return h.maxKeystoresPerKey()
}
