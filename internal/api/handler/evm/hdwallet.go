package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

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
	readOnly           bool // when true, block HD wallet creation/derive via API
	maxHDWalletsPerKey int  // resource limit: max HD wallets per API key (0 = no limit)
	logger             *slog.Logger
	auditLogger        *audit.AuditLogger // optional: audit logging
}

// SetAuditLogger sets the audit logger for HD wallet operations.
func (h *HDWalletHandler) SetAuditLogger(al *audit.AuditLogger) {
	h.auditLogger = al
}

// SetMaxHDWalletsPerKey sets the resource limit for maximum HD wallets per API key.
func (h *HDWalletHandler) SetMaxHDWalletsPerKey(max int) {
	h.maxHDWalletsPerKey = max
}

// NewHDWalletHandler creates a new HD wallet handler.
func NewHDWalletHandler(signerManager evmchain.SignerManager, accessService *service.SignerAccessService, logger *slog.Logger, readOnly bool) (*HDWalletHandler, error) {
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

type createHDWalletRequest struct {
	Action   string `json:"action"` // "create" or "import"
	Password string `json:"password"`

	// For import
	Mnemonic string `json:"mnemonic,omitempty"`

	// For create
	EntropyBits int `json:"entropy_bits,omitempty"`
}

type hdWalletResponse struct {
	PrimaryAddress string               `json:"primary_address"`
	BasePath       string               `json:"base_path"`
	DerivedCount   int                  `json:"derived_count"`
	Derived        []signerInfoResponse `json:"derived,omitempty"`
	Locked         bool                 `json:"locked"`
	DisplayName    string               `json:"display_name,omitempty"`
	Tags           []string             `json:"tags,omitempty"`
}

type signerInfoResponse struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

type deriveRequest struct {
	Index *uint32 `json:"index,omitempty"`
	Start *uint32 `json:"start,omitempty"`
	Count *uint32 `json:"count,omitempty"`
}

type listHDWalletsResponse struct {
	Wallets []hdWalletResponse `json:"wallets"`
}

type listDerivedResponse struct {
	Derived []signerInfoResponse `json:"derived"`
}

type deriveResponse struct {
	Derived []signerInfoResponse `json:"derived"`
}

// --- Handlers ---

// ServeHTTP handles /api/v1/evm/hd-wallets
func (h *HDWalletHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Strip prefix to get the rest of the path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/hd-wallets")
	path = strings.TrimSuffix(path, "/")

	switch {
	case path == "" || path == "/":
		switch r.Method {
		case http.MethodPost:
			// Create/import requires admin
			if !apiKey.IsAdmin() {
				h.writeError(w, "admin access required", http.StatusForbidden)
				return
			}
			h.createOrImport(w, r)
		case http.MethodGet:
			h.listWallets(w, r)
		default:
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		// Parse: /{address}/derive or /{address}/derived
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
		if len(parts) < 1 || !validate.IsValidEthereumAddress(parts[0]) {
			h.writeError(w, "invalid path or address", http.StatusBadRequest)
			return
		}
		address := parts[0]

		// Per-wallet actions: check ownership/access
		allowed, accessErr := h.accessService.CheckAccess(r.Context(), apiKey.ID, address)
		if accessErr != nil {
			h.writeError(w, "failed to check access", http.StatusInternalServerError)
			return
		}
		if !allowed {
			h.writeError(w, "not authorized for this HD wallet", http.StatusForbidden)
			return
		}

		action := ""
		if len(parts) == 2 {
			action = parts[1]
		}

		switch action {
		case "derive":
			if r.Method != http.MethodPost {
				h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h.deriveAddresses(w, r, address)
		case "derived":
			if r.Method != http.MethodGet {
				h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h.listDerived(w, r, address)
		default:
			h.writeError(w, "unknown action", http.StatusNotFound)
		}
	}
}

func (h *HDWalletHandler) createOrImport(w http.ResponseWriter, r *http.Request) {
	if h.readOnly {
		h.writeError(w, "HD wallet creation via API is disabled (security.signers_api_readonly)", http.StatusForbidden)
		return
	}

	// Enforce resource limit: max HD wallets per key
	if h.maxHDWalletsPerKey > 0 {
		apiKey := middleware.GetAPIKey(r.Context())
		if apiKey != nil {
			// BUGFIX: Count only HD wallets, not all signer types
			count, countErr := h.accessService.CountOwnedHDWallets(r.Context(), apiKey.ID)
			if countErr != nil {
				h.logger.Error("failed to count owned HD wallets", slog.String("error", countErr.Error()))
				h.writeError(w, "failed to check resource limits", http.StatusInternalServerError)
				return
			}
			if int(count) >= h.maxHDWalletsPerKey {
				h.writeError(w, fmt.Sprintf("resource limit exceeded: maximum %d HD wallets per API key", h.maxHDWalletsPerKey), http.StatusForbidden)
				return
			}
		}
	}

	mgr, err := h.signerManager.HDWalletManager()
	if err != nil {
		h.writeError(w, err.Error(), http.StatusNotImplemented)
		return
	}

	var req createHDWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer func() {
		secure.ZeroString(&req.Password)
		secure.ZeroString(&req.Mnemonic)
	}()

	if req.Password == "" {
		h.writeError(w, "password is required", http.StatusBadRequest)
		return
	}

	var info *evmchain.HDWalletInfo

	switch req.Action {
	case "import":
		if req.Mnemonic == "" {
			h.writeError(w, "mnemonic is required for import", http.StatusBadRequest)
			return
		}
		info, err = mgr.ImportHDWallet(r.Context(), types.ImportHDWalletParams{
			Mnemonic: req.Mnemonic,
			Password: req.Password,
		})
	case "create", "":
		info, err = mgr.CreateHDWallet(r.Context(), types.CreateHDWalletParams{
			Password:    req.Password,
			EntropyBits: req.EntropyBits,
		})
	default:
		h.writeError(w, "action must be 'create' or 'import'", http.StatusBadRequest)
		return
	}

	if err != nil {
		h.logger.Error("HD wallet operation failed",
			slog.String("action", req.Action),
			slog.String("error", err.Error()),
		)
		if strings.Contains(err.Error(), "already exists") {
			h.writeError(w, err.Error(), http.StatusConflict)
			return
		}
		h.writeError(w, err.Error(), http.StatusInternalServerError)
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
		h.auditLogger.LogHDWalletCreated(r.Context(), keyID, r.RemoteAddr, info.PrimaryAddress, action)
	}

	h.writeJSON(w, h.hdWalletResponse(r.Context(), info), http.StatusCreated)
}

func (h *HDWalletHandler) listWallets(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	mgr, err := h.signerManager.HDWalletManager()
	if err != nil {
		h.writeError(w, err.Error(), http.StatusNotImplemented)
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

	resp := listHDWalletsResponse{
		Wallets: make([]hdWalletResponse, len(filtered)),
	}
	for i := range filtered {
		resp.Wallets[i] = h.hdWalletResponse(r.Context(), &filtered[i])
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *HDWalletHandler) deriveAddresses(w http.ResponseWriter, r *http.Request, primaryAddr string) {
	if h.readOnly {
		h.writeError(w, "HD wallet derive via API is disabled (security.signers_api_readonly)", http.StatusForbidden)
		return
	}

	mgr, err := h.signerManager.HDWalletManager()
	if err != nil {
		h.writeError(w, err.Error(), http.StatusNotImplemented)
		return
	}

	var req deriveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var derived []types.SignerInfo

	if req.Index != nil {
		// Single derive
		info, err := mgr.DeriveAddress(r.Context(), primaryAddr, *req.Index)
		if err != nil {
			h.logger.Error("derive address failed",
				slog.String("primary_address", primaryAddr),
				slog.String("error", err.Error()),
			)
			h.writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		derived = append(derived, *info)
	} else if req.Start != nil && req.Count != nil {
		if *req.Count == 0 || *req.Count > 100 {
			h.writeError(w, "count must be between 1 and 100", http.StatusBadRequest)
			return
		}
		infos, err := mgr.DeriveAddresses(r.Context(), primaryAddr, *req.Start, *req.Count)
		if err != nil {
			h.logger.Error("derive addresses failed",
				slog.String("primary_address", primaryAddr),
				slog.String("error", err.Error()),
			)
			h.writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		derived = infos
	} else {
		h.writeError(w, "either 'index' or 'start'+'count' is required", http.StatusBadRequest)
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

	resp := deriveResponse{
		Derived: toSignerInfoResponseList(derived),
	}
	h.writeJSON(w, resp, http.StatusOK)
}

func (h *HDWalletHandler) listDerived(w http.ResponseWriter, r *http.Request, primaryAddr string) {
	mgr, err := h.signerManager.HDWalletManager()
	if err != nil {
		h.writeError(w, err.Error(), http.StatusNotImplemented)
		return
	}

	derived, err := mgr.ListDerivedAddresses(primaryAddr)
	if err != nil {
		h.logger.Error("list derived addresses failed",
			slog.String("primary_address", primaryAddr),
			slog.String("error", err.Error()),
		)
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := listDerivedResponse{
		Derived: toSignerInfoResponseList(derived),
	}
	h.writeJSON(w, resp, http.StatusOK)
}

// --- Helpers ---

func (h *HDWalletHandler) hdWalletResponse(ctx context.Context, info *evmchain.HDWalletInfo) hdWalletResponse {
	out := hdWalletResponse{
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

func toSignerInfoResponseList(infos []types.SignerInfo) []signerInfoResponse {
	result := make([]signerInfoResponse, len(infos))
	for i, info := range infos {
		result[i] = signerInfoResponse{
			Address: info.Address,
			Type:    info.Type,
			Enabled: info.Enabled,
		}
	}
	return result
}

func (h *HDWalletHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", slog.String("error", err.Error()))
	}
}

func (h *HDWalletHandler) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
