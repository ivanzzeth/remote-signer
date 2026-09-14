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
	// Rejected when empty: 400 "new_owner_id is required".
	NewOwnerID string `json:"new_owner_id" binding:"required"`
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
//
//	@Summary	List signers
//	@Description	⛔ Scoped per caller: a non-admin is pinned to its own signers, and naming another key in `api_key_id` is 403 rather than an empty list. `ownership_status=pending_approval` is admin-only, also 403.
//	@Description	⚠️ `locked` and `enabled` are tri-state: absent means no filter, and anything that is not `true`/`false` is a 400.
//	@Description	⚠️ `exclude_hd_derived` only recognises `true` and `1`; any other value leaves derived addresses in.
//	@Tags	signers
//	@Produce	json
//	@Param	type	query	string	false	"private_key or keystore; 400 otherwise"
//	@Param	tag	query	string	false	"restrict to signers carrying this tag"
//	@Param	api_key_id	query	string	false	"admin only; 403 for anyone else naming another key"
//	@Param	locked	query	string	false	"true or false; 400 otherwise"
//	@Param	enabled	query	string	false	"true or false; 400 otherwise"
//	@Param	ownership_status	query	string	false	"only pending_approval is accepted, and only for admin"
//	@Param	exclude_hd_derived	query	string	false	"true or 1 to hide HD-derived addresses"
//	@Param	limit	query	int	false	"maximum rows"
//	@Param	offset	query	int	false	"rows to skip"
//	@Success	200	{object}	ListSignersResponse
//	@Failure	400	{object}	map[string]string
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"filtering by another api key, or listing pending approvals without admin"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers [get]
func (h *SignerHandler) ListSigners(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.listSigners(w, r)
}

// CreateSigner serves POST /api/v1/evm/signers.
//
//	@Summary	Create a signer
//	@Description	⛔ A signer created by a NON-ADMIN key lands in pending_approval and cannot sign until an admin calls the approve endpoint. The 201 does not tell you which happened — check the signer's ownership status.
//	@Description	⚠️ Three creation modes share one body, chosen inside `keystore`: both import fields empty generates a fresh keypair, `private_key_hex` imports a raw key, `keystore_json` imports a v3 keystore. Sending both import fields is 400.
//	@Description	⛔ Password, private key and keystore JSON are zeroised after handoff and never echoed back; the response carries only the address and labels.
//	@Description	⚠️ A failure to record ownership is logged but does NOT fail the 201 — the signer exists with no owner and has to be fixed by hand.
//	@Tags	signers
//	@Accept	json
//	@Produce	json
//	@Param	body	body	CreateSignerRequest	true	"signer to create or import"
//	@Success	201	{object}	CreateSignerResponse
//	@Failure	400	{object}	map[string]string	"missing or unsupported type, missing keystore params, empty password, or both import fields set"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"read-only mode, or the per-key keystore limit is reached"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers [post]
func (h *SignerHandler) CreateSigner(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.createSigner(w, r)
}

// DeleteSigner serves DELETE /api/v1/evm/signers/{address}.
//
//	@Summary	Delete a signer
//	@Description	⛔ Owner only: a signer owned by someone else answers 403 and a signer that does not exist answers 404 — these are NOT merged, so the pair is distinguishable.
//	@Tags	signers
//	@Produce	json
//	@Param	address	path	string	true	"signer address; not format-checked here, an unknown one is 404"
//	@Success	204	"deleted; no body"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"only the signer owner may do this"
//	@Failure	404	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address} [delete]
func (h *SignerHandler) DeleteSigner(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleDeleteSigner(w, r, address)
}

// PatchSignerLabels serves PATCH /api/v1/evm/signers/{address}.
//
//	@Summary	Update a signer's labels
//	@Description	Owner only. Changes display name and tags; nothing else about a signer is editable through this endpoint.
//	@Description	⚠️ An empty body is 400 — at least one of the two fields must be present. Present-but-null clears a label.
//	@Tags	signers
//	@Accept	json
//	@Produce	json
//	@Param	address	path	string	true	"signer address"
//	@Param	body	body	PatchSignerLabelsRequest	true	"at least one of display_name or tags"
//	@Success	200	{object}	SignerResponse
//	@Failure	400	{object}	map[string]string	"empty body, or a rejected label value"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"only the signer owner may do this"
//	@Failure	404	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address} [patch]
func (h *SignerHandler) PatchSignerLabels(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handlePatchSignerLabels(w, r, address)
}

// Unlock serves POST /api/v1/evm/signers/{address}/unlock.
//
//	@Summary	Unlock a signer
//	@Description	Owner only. Decrypts the keystore into memory so the signer can sign; how long it stays unlocked is security.auto_lock_timeout, not a parameter here.
//	@Description	⚠️ An already-unlocked signer is 409, not a no-op 200.
//	@Tags	signers
//	@Accept	json
//	@Produce	json
//	@Param	address	path	string	true	"signer address"
//	@Param	body	body	UnlockSignerRequest	true	"keystore password"
//	@Success	200	{object}	SignerResponse
//	@Failure	400	{object}	map[string]string	"bad body or empty password"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"only the signer owner may do this"
//	@Failure	404	{object}	map[string]string
//	@Failure	409	{object}	map[string]string	"already unlocked"
//	@Failure	500	{object}	map[string]string	"also the answer for a WRONG password — it is not distinguished from an internal failure"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address}/unlock [post]
func (h *SignerHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleUnlock(w, r, address)
}

// Lock serves POST /api/v1/evm/signers/{address}/lock.
//
//	@Summary	Lock a signer
//	@Description	Owner only. Drops the decrypted key from memory. Takes no request body.
//	@Description	⚠️ An already-locked signer is 409, not a no-op 200.
//	@Tags	signers
//	@Produce	json
//	@Param	address	path	string	true	"signer address"
//	@Success	200	{object}	SignerResponse
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"only the signer owner may do this"
//	@Failure	404	{object}	map[string]string
//	@Failure	409	{object}	map[string]string	"already locked"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address}/lock [post]
func (h *SignerHandler) Lock(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleLock(w, r, address)
}

// ApproveSigner serves POST /api/v1/evm/signers/{address}/approve.
//
//	@Summary	Approve a pending signer
//	@Description	Moves a signer's ownership from pending_approval to active, which is what lets it sign at all. Takes no request body.
//	@Description	⛔ Admin ROLE only, checked in the handler as 403 — the route's read_signers permission is not what gates this.
//	@Description	⚠️ An already-active signer is 409, and a signer with no ownership record at all is 404.
//	@Tags	signers
//	@Produce	json
//	@Param	address	path	string	true	"signer address"
//	@Success	200	{object}	map[string]string	"keys `status` and `signer_address`"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"admin role required"
//	@Failure	404	{object}	map[string]string	"no ownership record for this signer"
//	@Failure	409	{object}	map[string]string	"already active"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address}/approve [post]
func (h *SignerHandler) ApproveSigner(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleApproveSigner(w, r, address)
}

// TransferOwnership serves POST /api/v1/evm/signers/{address}/transfer.
//
//	@Summary	Transfer a signer to another api key
//	@Description	⚠️ Hands the signer to `new_owner_id`, so the CALLER loses it. Existing access grants are not part of this response.
//	@Tags	signers
//	@Accept	json
//	@Produce	json
//	@Param	address	path	string	true	"signer address"
//	@Param	body	body	TransferOwnershipRequest	true	"the api key that should own it"
//	@Success	200	{object}	map[string]string	"keys describing the completed transfer"
//	@Failure	400	{object}	map[string]string	"bad body, missing new_owner_id, or a new owner the service refuses"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"only the signer owner may do this"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address}/transfer [post]
func (h *SignerHandler) TransferOwnership(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleTransferOwnership(w, r, address)
}

// ListAccess serves GET /api/v1/evm/signers/{address}/access.
//
//	@Summary	List a signer's access grants
//	@Description	⚠️ Returns a bare JSON ARRAY, not an object with a key.
//	@Description	⛔ Every failure from the access service is flattened to 403 with the service's own message — including a signer that does not exist. There is no 404 on this endpoint.
//	@Tags	signers
//	@Produce	json
//	@Param	address	path	string	true	"signer address"
//	@Success	200	{array}	SignerAccessResponse
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"not permitted, or the signer does not exist — the two are not distinguished"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address}/access [get]
func (h *SignerHandler) ListAccess(w http.ResponseWriter, r *http.Request) {
	address, ok := h.signerAddress(w, r)
	if !ok {
		return
	}
	h.handleListAccess(w, r, address)
}

// GrantAccess serves POST /api/v1/evm/signers/{address}/access.
//
//	@Summary	Grant another api key access to a signer
//	@Description	Access is not ownership: the grantee may use the signer, the owner stays the owner.
//	@Description	⛔ Every failure from the access service is flattened to 403, so "already granted", "no such signer" and "you may not grant this" arrive with the same status and differ only in the message.
//	@Tags	signers
//	@Accept	json
//	@Produce	json
//	@Param	address	path	string	true	"signer address"
//	@Param	body	body	GrantAccessRequest	true	"the api key to grant"
//	@Success	200	{object}	map[string]string	"keys `status`, `signer_address`, `api_key_id`"
//	@Failure	400	{object}	map[string]string	"bad body or missing api_key_id"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"any refusal from the access service"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address}/access [post]
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
//
//	@Summary	Revoke an api key's access to a signer
//	@Description	Takes no request body. ⚠️ Answers 200 with a body, not 204.
//	@Description	⛔ Every failure from the access service is flattened to 403, including a grant that never existed — there is no 404 here.
//	@Tags	signers
//	@Produce	json
//	@Param	address	path	string	true	"signer address"
//	@Param	keyID	path	string	true	"the api key whose grant is being revoked"
//	@Success	200	{object}	map[string]string	"keys `status`, `signer_address`, `api_key_id`"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"any refusal from the access service"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/signers/{address}/access/{keyID} [delete]
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
