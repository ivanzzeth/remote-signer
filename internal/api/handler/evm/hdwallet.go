package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/secure"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// HDWalletHandler handles HD wallet management endpoints.
type HDWalletHandler struct {
	signerManager      evmchain.SignerManager
	accessService      *service.SignerAccessService
	readOnly           func() bool // when true, block HD wallet creation/derive via API
	maxHDWalletsPerKey func() int  // resource limit: max HD wallets per API key (0 = no limit)
	logger             *slog.Logger
	auditLogger        *audit.AuditLogger // optional: audit logging
}

// SetAuditLogger sets the audit logger for HD wallet operations.
func (h *HDWalletHandler) SetAuditLogger(al *audit.AuditLogger) {
	h.auditLogger = al
}

// SetMaxHDWalletsPerKey sets the resource limit for maximum HD wallets per API key.
func (h *HDWalletHandler) SetMaxHDWalletsPerKey(max func() int) {
	h.maxHDWalletsPerKey = max
}

// NewHDWalletHandler creates a new HD wallet handler.
func NewHDWalletHandler(signerManager evmchain.SignerManager, accessService *service.SignerAccessService, logger *slog.Logger, readOnly func() bool) (*HDWalletHandler, error) {
	if signerManager == nil {
		return nil, fmt.Errorf("signer manager is required")
	}
	if accessService == nil {
		return nil, fmt.Errorf("access service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &HDWalletHandler{
		signerManager: signerManager,
		accessService: accessService,
		readOnly:      readOnly,
		logger:        logger,
	}, nil
}

// --- Request/Response types ---
//
// ⚠️ Exported, and the reason is not style — it is the same one wallet.go
// records for its seven (proposal §1.4, §3.3). These are the HD-wallet API's
// wire contract, and the plan they belong to turns each into a schema name in a
// generated OpenAPI document and from there into a type name in the generated Go
// and TypeScript SDKs. A generator has nothing to call an unexported type: it
// invents an unreadable name or inlines an anonymous schema, and either way the
// SDK stops matching the handler by name.
//
// ⛔ The JSON tags are the actual contract and not one of them changed here. A
// field name a client parses lives in the tag, not in the Go identifier — so
// this rename is invisible on the wire.

// CreateHDWalletRequest is the body of POST /api/v1/evm/hd-wallets.
type CreateHDWalletRequest struct {
	Action   string `json:"action"` // "create" or "import"
	Password string `json:"password"`

	// For import — exactly one of Mnemonic / WalletJSON should be set.
	Mnemonic   string `json:"mnemonic,omitempty"`
	WalletJSON string `json:"wallet_json,omitempty"`

	// For create
	EntropyBits int `json:"entropy_bits,omitempty"`
}

// HDWalletResponse is one HD wallet as the API returns it.
type HDWalletResponse struct {
	PrimaryAddress string               `json:"primary_address"`
	BasePath       string               `json:"base_path"`
	DerivedCount   int                  `json:"derived_count"`
	Derived        []SignerInfoResponse `json:"derived,omitempty"`
	Locked         bool                 `json:"locked"`
	DisplayName    string               `json:"display_name,omitempty"`
	Tags           []string             `json:"tags,omitempty"`
}

// SignerInfoResponse is one derived signer as the HD-wallet endpoints return it.
type SignerInfoResponse struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	// Mirror types.SignerInfo's full surface so the web UI's HD wallet
	// detail panel can render derivation index, lock state, and the
	// parent-address backreference. Earlier versions dropped these
	// fields here on the way out, so listDerived's JSON looked like
	// {address, type, enabled} only — the UI fell back to "—" for
	// every index column.
	Locked            bool    `json:"locked"`
	HDParentAddress   string  `json:"hd_parent_address,omitempty"`
	HDDerivationIndex *uint32 `json:"hd_derivation_index,omitempty"`
}

// DeriveRequest is the body of POST /api/v1/evm/hd-wallets/{address}/derive:
// either Index alone, or Start plus Count.
type DeriveRequest struct {
	Index *uint32 `json:"index,omitempty"`
	Start *uint32 `json:"start,omitempty"`
	Count *uint32 `json:"count,omitempty"`
}

// ListHDWalletsResponse is the body of GET /api/v1/evm/hd-wallets.
type ListHDWalletsResponse struct {
	Wallets []HDWalletResponse `json:"wallets"`
}

// ListDerivedResponse is the body of GET /api/v1/evm/hd-wallets/{address}/derived.
type ListDerivedResponse struct {
	Derived []SignerInfoResponse `json:"derived"`
}

// DeriveResponse is the body of POST /api/v1/evm/hd-wallets/{address}/derive.
type DeriveResponse struct {
	Derived []SignerInfoResponse `json:"derived"`
}

// --- Handler entry points ---
//
// # One exported function per endpoint (proposal S4, copying S3's shape)
//
// These four replace ServeHTTP, which took r.URL.Path apart with
// TrimPrefix/TrimSuffix/SplitN and fanned out into them. The registration that
// used to hide them behind two prefix patterns plus two method-scoped ones is
// internal/api/module_hdwallets.go, and it now names each one.
//
// ⭐ Why both halves had to move at once (proposal §1.3): two of these four
// patterns already carried an {address} wildcard, and the handler still ignored
// it and cut the path itself — so the wildcard was decorative and the same
// function stayed reachable from the prefix pattern. The address is read through
// r.PathValue here, which only a matching pattern can populate.
//
// ⛔ HDWalletHandler is deliberately no longer an http.Handler. It has no
// ServeHTTP, so there is no way to hand the whole HD-wallet surface to one
// pattern again by accident.
//
// ⚠️ Every guard ServeHTTP ran before dispatching is still run, in the same
// order and with the same words and status codes — see requireAPIKey and
// resolveAccessibleWallet. Only the dispatch left.

// ListWallets serves GET /api/v1/evm/hd-wallets.
func (h *HDWalletHandler) ListWallets(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAPIKey(w, r); !ok {
		return
	}
	h.listWallets(w, r)
}

// CreateOrImport serves POST /api/v1/evm/hd-wallets.
//
// ⛔ The admin check is the one ServeHTTP made for POST and it stays in the
// handler rather than moving to the route. The route carries no permission at
// all (internal/api/module_hdwallets.go records why), so removing this check
// would open creation to every authenticated key — which is a strictly larger
// hole than the one already recorded there.
func (h *HDWalletHandler) CreateOrImport(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := h.requireAPIKey(w, r)
	if !ok {
		return
	}
	if !apiKey.IsAdmin() {
		respond.Error(w, "admin access required", http.StatusForbidden, h.logger)
		return
	}
	h.createOrImport(w, r)
}

// Derive serves POST /api/v1/evm/hd-wallets/{address}/derive.
func (h *HDWalletHandler) Derive(w http.ResponseWriter, r *http.Request) {
	address, ok := h.resolveAccessibleWallet(w, r)
	if !ok {
		return
	}
	h.deriveAddresses(w, r, address)
}

// ListDerived serves GET /api/v1/evm/hd-wallets/{address}/derived.
func (h *HDWalletHandler) ListDerived(w http.ResponseWriter, r *http.Request) {
	address, ok := h.resolveAccessibleWallet(w, r)
	if !ok {
		return
	}
	h.listDerived(w, r, address)
}

// requireAPIKey is the 401 ServeHTTP answered at its top, before it looked at
// the path at all. ⚠️ It is not redundant with the middleware chain: these
// routes are AuthenticatedOnly, so a request reaching them has a key — but the
// handler is also called directly by tests, and listWallets dereferences the key
// without checking it.
func (h *HDWalletHandler) requireAPIKey(w http.ResponseWriter, r *http.Request) (*types.APIKey, bool) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return nil, false
	}
	return apiKey, true
}

// resolveAccessibleWallet is the block ServeHTTP ran for every path with an
// address in it, called by each of the two {address} routes instead.
//
// ⛔ Its four answers are copied verbatim and their order matters, because each
// one is what a caller learns: no API key is 401; a first segment that is not an
// EVM address is 400 "invalid path or address"; a failing access lookup is 500;
// and a wallet this key may not touch is 403 "not authorized for this HD
// wallet". ⚠️ Reordering the access check, or turning the 403 into a 404, is a
// security change wearing a refactor's clothes.
func (h *HDWalletHandler) resolveAccessibleWallet(w http.ResponseWriter, r *http.Request) (string, bool) {
	apiKey, ok := h.requireAPIKey(w, r)
	if !ok {
		return "", false
	}

	address := r.PathValue("address")
	if !validate.IsValidEthereumAddress(address) {
		respond.Error(w, "invalid path or address", http.StatusBadRequest, h.logger)
		return "", false
	}

	allowed, accessErr := h.accessService.CheckAccess(r.Context(), apiKey.ID, address)
	if accessErr != nil {
		respond.Error(w, "failed to check access", http.StatusInternalServerError, h.logger)
		return "", false
	}
	if !allowed {
		respond.Error(w, "not authorized for this HD wallet", http.StatusForbidden, h.logger)
		return "", false
	}
	return address, true
}

func (h *HDWalletHandler) createOrImport(w http.ResponseWriter, r *http.Request) {
	if h.isReadOnly() {
		respond.Error(w, "HD wallet creation via API is disabled (security.signers_api_readonly)", http.StatusForbidden, h.logger)
		return
	}

	// Enforce resource limit: max HD wallets per key
	if h.maxHDWalletsPerKeyValue() > 0 {
		apiKey := middleware.GetAPIKey(r.Context())
		if apiKey != nil {
			// BUGFIX: Count only HD wallets, not all signer types
			count, countErr := h.accessService.CountOwnedHDWallets(r.Context(), apiKey.ID)
			if countErr != nil {
				h.logger.Error("failed to count owned HD wallets", slog.String("error", countErr.Error()))
				respond.Error(w, "failed to check resource limits", http.StatusInternalServerError, h.logger)
				return
			}
			if int(count) >= h.maxHDWalletsPerKeyValue() {
				respond.Error(w, fmt.Sprintf("resource limit exceeded: maximum %d HD wallets per API key", h.maxHDWalletsPerKeyValue()), http.StatusForbidden, h.logger)
				return
			}
		}
	}

	mgr, err := h.signerManager.HDWalletManager()
	if err != nil {
		respond.Error(w, err.Error(), http.StatusNotImplemented, h.logger)
		return
	}

	var req CreateHDWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}
	defer func() {
		secure.ZeroString(&req.Password)
		secure.ZeroString(&req.Mnemonic)
		// WalletJSON has the encrypted mnemonic envelope; not as sensitive
		// as the cleartext mnemonic but still discardable post-import.
		secure.ZeroString(&req.WalletJSON)
	}()

	if req.Password == "" {
		respond.Error(w, "password is required", http.StatusBadRequest, h.logger)
		return
	}

	var info *evmchain.HDWalletInfo

	switch req.Action {
	case "import":
		if req.Mnemonic == "" && req.WalletJSON == "" {
			respond.Error(w, "mnemonic or wallet_json is required for import", http.StatusBadRequest, h.logger)
			return
		}
		if req.Mnemonic != "" && req.WalletJSON != "" {
			respond.Error(w, "specify either mnemonic or wallet_json, not both", http.StatusBadRequest, h.logger)
			return
		}
		info, err = mgr.ImportHDWallet(r.Context(), types.ImportHDWalletParams{
			Mnemonic:   req.Mnemonic,
			WalletJSON: req.WalletJSON,
			Password:   req.Password,
		})
	case "create", "":
		info, err = mgr.CreateHDWallet(r.Context(), types.CreateHDWalletParams{
			Password:    req.Password,
			EntropyBits: req.EntropyBits,
		})
	default:
		respond.Error(w, "action must be 'create' or 'import'", http.StatusBadRequest, h.logger)
		return
	}

	if err != nil {
		h.logger.Error("HD wallet operation failed",
			slog.String("action", req.Action),
			slog.String("error", err.Error()),
		)
		if strings.Contains(err.Error(), "already exists") {
			respond.Error(w, err.Error(), http.StatusConflict, h.logger)
			return
		}
		respond.Error(w, err.Error(), http.StatusInternalServerError, h.logger)
		return
	}

	// Set ownership for the newly created HD wallet's primary address
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey != nil {
		status := types.SignerOwnershipPendingApproval
		if apiKey.IsAdmin() {
			status = types.SignerOwnershipActive
		}
		if ownerErr := h.accessService.SetOwnerWithType(r.Context(), info.PrimaryAddress, apiKey.ID, status, types.SignerTypeHDWallet); ownerErr != nil {
			h.logger.Error("failed to set HD wallet ownership",
				slog.String("address", info.PrimaryAddress),
				slog.String("error", ownerErr.Error()),
			)
			// Non-fatal: wallet was created, ownership can be fixed manually
		}
	}

	if h.auditLogger != nil {
		keyID := ""
		if apiKey != nil {
			keyID = apiKey.ID
		}
		action := req.Action
		if action == "" {
			action = "create"
		}
		// Differentiate the two import flavours so the audit trail records
		// whether the operator pasted a mnemonic or uploaded a wallet JSON.
		if action == "import" {
			if req.WalletJSON != "" {
				action = "import:wallet-json"
			} else {
				action = "import:mnemonic"
			}
		}
		h.auditLogger.LogHDWalletCreated(r.Context(), keyID, r.RemoteAddr, info.PrimaryAddress, action)
	}

	respond.JSON(w, h.hdWalletResponse(r.Context(), info), http.StatusCreated, h.logger)
}

func (h *HDWalletHandler) listWallets(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	mgr, err := h.signerManager.HDWalletManager()
	if err != nil {
		respond.Error(w, err.Error(), http.StatusNotImplemented, h.logger)
		return
	}

	wallets := mgr.ListHDWallets()

	// Filter by ownership/access
	var filtered []evmchain.HDWalletInfo
	for _, wallet := range wallets {
		allowed, accessErr := h.accessService.CheckAccess(r.Context(), apiKey.ID, wallet.PrimaryAddress)
		if accessErr != nil {
			continue
		}
		if allowed {
			filtered = append(filtered, wallet)
		}
	}

	resp := ListHDWalletsResponse{
		Wallets: make([]HDWalletResponse, len(filtered)),
	}
	for i := range filtered {
		resp.Wallets[i] = h.hdWalletResponse(r.Context(), &filtered[i])
	}

	respond.JSON(w, resp, http.StatusOK, h.logger)
}

func (h *HDWalletHandler) deriveAddresses(w http.ResponseWriter, r *http.Request, primaryAddr string) {
	if h.isReadOnly() {
		respond.Error(w, "HD wallet derive via API is disabled (security.signers_api_readonly)", http.StatusForbidden, h.logger)
		return
	}

	mgr, err := h.signerManager.HDWalletManager()
	if err != nil {
		respond.Error(w, err.Error(), http.StatusNotImplemented, h.logger)
		return
	}

	var req DeriveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	var derived []types.SignerInfo

	if req.Index != nil {
		// Single derive
		info, err := mgr.DeriveAddress(r.Context(), primaryAddr, *req.Index)
		if err != nil {
			if strings.Contains(err.Error(), "is locked") {
				respond.Error(w, err.Error(), http.StatusLocked, h.logger)
				return
			}
			h.logger.Error("derive address failed",
				slog.String("primary_address", primaryAddr),
				slog.String("error", err.Error()),
			)
			respond.Error(w, err.Error(), http.StatusInternalServerError, h.logger)
			return
		}
		derived = append(derived, *info)
	} else if req.Start != nil && req.Count != nil {
		if *req.Count == 0 || *req.Count > 100 {
			respond.Error(w, "count must be between 1 and 100", http.StatusBadRequest, h.logger)
			return
		}
		infos, err := mgr.DeriveAddresses(r.Context(), primaryAddr, *req.Start, *req.Count)
		if err != nil {
			if strings.Contains(err.Error(), "is locked") {
				respond.Error(w, err.Error(), http.StatusLocked, h.logger)
				return
			}
			h.logger.Error("derive addresses failed",
				slog.String("primary_address", primaryAddr),
				slog.String("error", err.Error()),
			)
			respond.Error(w, err.Error(), http.StatusInternalServerError, h.logger)
			return
		}
		derived = infos
	} else {
		respond.Error(w, "either 'index' or 'start'+'count' is required", http.StatusBadRequest, h.logger)
		return
	}

	if h.auditLogger != nil {
		apiKey := middleware.GetAPIKey(r.Context())
		keyID := ""
		if apiKey != nil {
			keyID = apiKey.ID
		}
		h.auditLogger.LogHDWalletDerived(r.Context(), keyID, r.RemoteAddr, primaryAddr, len(derived))
	}

	resp := DeriveResponse{
		Derived: toSignerInfoResponseList(derived),
	}
	respond.JSON(w, resp, http.StatusOK, h.logger)
}

func (h *HDWalletHandler) listDerived(w http.ResponseWriter, r *http.Request, primaryAddr string) {
	mgr, err := h.signerManager.HDWalletManager()
	if err != nil {
		respond.Error(w, err.Error(), http.StatusNotImplemented, h.logger)
		return
	}

	derived, err := mgr.ListDerivedAddresses(primaryAddr)
	if err != nil {
		// "is locked … (unlock first)" is operational state, not an
		// internal error — return 423 so the UI can render a friendly
		// "Unlock first" hint without staring at a 500.
		if strings.Contains(err.Error(), "is locked") {
			respond.Error(w, err.Error(), http.StatusLocked, h.logger)
			return
		}
		h.logger.Error("list derived addresses failed",
			slog.String("primary_address", primaryAddr),
			slog.String("error", err.Error()),
		)
		respond.Error(w, err.Error(), http.StatusInternalServerError, h.logger)
		return
	}

	resp := ListDerivedResponse{
		Derived: toSignerInfoResponseList(derived),
	}
	respond.JSON(w, resp, http.StatusOK, h.logger)
}

// --- Helpers ---

func (h *HDWalletHandler) hdWalletResponse(ctx context.Context, info *evmchain.HDWalletInfo) HDWalletResponse {
	out := HDWalletResponse{
		PrimaryAddress: info.PrimaryAddress,
		BasePath:       info.BasePath,
		DerivedCount:   info.DerivedCount,
		Derived:        toSignerInfoResponseList(info.Derived),
		Locked:         info.Locked,
	}
	if own, err := h.accessService.GetOwnership(ctx, info.PrimaryAddress); err == nil && own != nil {
		out.DisplayName = own.DisplayName
		out.Tags = own.Tags()
	}
	return out
}

func toSignerInfoResponseList(infos []types.SignerInfo) []SignerInfoResponse {
	result := make([]SignerInfoResponse, len(infos))
	for i, info := range infos {
		result[i] = SignerInfoResponse{
			Address:           info.Address,
			Type:              info.Type,
			Enabled:           info.Enabled,
			Locked:            info.Locked,
			HDParentAddress:   info.HDParentAddress,
			HDDerivationIndex: info.HDDerivationIndex,
		}
	}
	return result
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
func (h *HDWalletHandler) isReadOnly() bool {
	if h.readOnly == nil {
		return false
	}
	return h.readOnly()
}

// maxHDWalletsPerKeyValue reads the limit at request time. See Router.liveInt: the setting
// behind it is runtime mutable, so a value captured at construction freezes at
// boot. nil means unset, which these fields already meant as 0.
func (h *HDWalletHandler) maxHDWalletsPerKeyValue() int {
	if h.maxHDWalletsPerKey == nil {
		return 0
	}
	return h.maxHDWalletsPerKey()
}
