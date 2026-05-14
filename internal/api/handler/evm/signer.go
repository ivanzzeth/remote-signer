package evm

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

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
	readOnly           bool // when true, block signer creation via API
	maxKeystoresPerKey int  // resource limit: max keystores per API key (0 = no limit)
	logger             *slog.Logger
	auditLogger        *audit.AuditLogger // optional: audit logging
}

// TransferOwnershipRequest represents the request to transfer signer ownership.
type TransferOwnershipRequest struct {
	NewOwnerID string `json:"new_owner_id"`
}

// NewSignerHandler creates a new signer handler
func NewSignerHandler(signerManager evm.SignerManager, accessService *service.SignerAccessService, logger *slog.Logger, readOnly bool) (*SignerHandler, error) {
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
func (h *SignerHandler) SetMaxKeystoresPerKey(max int) {
	h.maxKeystoresPerKey = max
}

// ServeHTTP handles /api/v1/evm/signers
func (h *SignerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listSigners(w, r)
	case http.MethodPost:
		h.createSigner(w, r)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleSignerAction handles /api/v1/evm/signers/{address}/{action}
func (h *SignerHandler) HandleSignerAction(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse path: /api/v1/evm/signers/{address}[/{action}[/{extra}]]
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/signers/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 1 || parts[0] == "" {
		h.writeError(w, "invalid path: expected /api/v1/evm/signers/{address}", http.StatusBadRequest)
		return
	}

	address := parts[0]
	action := ""
	if len(parts) >= 2 {
		action = parts[1]
	}

	// Handle DELETE or PATCH /api/v1/evm/signers/{address} (no action segment)
	if action == "" {
		if r.Method == http.MethodDelete {
			h.handleDeleteSigner(w, r, address)
			return
		}
		if r.Method == http.MethodPatch {
			h.handlePatchSignerLabels(w, r, address)
			return
		}
		h.writeError(w, "invalid path: expected /api/v1/evm/signers/{address}/{action}", http.StatusBadRequest)
		return
	}

	switch action {
	case "unlock":
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleUnlock(w, r, address)
	case "lock":
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleLock(w, r, address)
	case "approve":
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleApproveSigner(w, r, address)
	case "transfer":
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleTransferOwnership(w, r, address)
	case "access":
		extra := ""
		if len(parts) == 3 {
			extra = parts[2]
		}
		h.handleAccess(w, r, address, extra)
	default:
		h.writeError(w, "unknown action: "+action, http.StatusBadRequest)
	}
}

// handleAccess routes access sub-actions
func (h *SignerHandler) handleAccess(w http.ResponseWriter, r *http.Request, address, extra string) {
	switch r.Method {
	case http.MethodGet:
		// GET /api/v1/evm/signers/{address}/access — list access
		h.handleListAccess(w, r, address)
	case http.MethodPost:
		// POST /api/v1/evm/signers/{address}/access — grant access
		h.handleGrantAccess(w, r, address)
	case http.MethodDelete:
		// DELETE /api/v1/evm/signers/{address}/access/{keyID}
		if extra == "" {
			h.writeError(w, "api_key_id is required in path", http.StatusBadRequest)
			return
		}
		h.handleRevokeAccess(w, r, address, extra)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleWalletSigners handles GET /api/v1/evm/wallets/{wallet_id}/signers
func (h *SignerHandler) HandleWalletSigners(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse wallet_id from path: /api/v1/evm/wallets/{wallet_id}/signers
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/wallets/")
	path = strings.TrimSuffix(path, "/signers")
	walletID := strings.TrimSpace(path)

	if walletID == "" {
		h.writeError(w, "wallet_id is required", http.StatusBadRequest)
		return
	}

	h.listWalletSigners(w, r, walletID)
}
