// Package evm provides HTTP handlers for EVM signer and rule management API.
// This file contains response/request types for the signer management endpoints.
package evm

import (
	"context"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignerResponse represents a signer in API responses
type SignerResponse struct {
	Address           string            `json:"address"`
	Type              string            `json:"type"`
	Enabled           bool              `json:"enabled"`
	Locked            bool              `json:"locked"`
	UnlockedAt        *time.Time        `json:"unlocked_at,omitempty"`
	OwnerID           string            `json:"owner_id,omitempty"`
	Status            string            `json:"status,omitempty"` // ownership status: active, pending_approval
	DisplayName       string            `json:"display_name,omitempty"`
	Tags              []string          `json:"tags,omitempty"`
	PrimaryAddress    string            `json:"primary_address,omitempty"`     // for HD derived: parent HD address; otherwise self
	HDDerivationIndex *uint32           `json:"hd_derivation_index,omitempty"` // for derived addresses: derivation index
	MaterialStatus    string            `json:"material_status,omitempty"`
	MaterialCheckedAt *time.Time        `json:"material_checked_at,omitempty"`
	MaterialMissingAt *time.Time        `json:"material_missing_at,omitempty"`
	Wallets           []SignerWalletRef `json:"wallets,omitempty"`
}

// SignerWalletRef references a wallet that contains this signer.
type SignerWalletRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// WalletResponse represents a wallet in API responses
type WalletResponse struct {
	WalletID       string     `json:"wallet_id"`
	WalletType     string     `json:"wallet_type"` // hd_wallet, keystore, etc.
	PrimaryAddress string     `json:"primary_address"`
	SignerCount    int        `json:"signer_count"` // number of signers under this wallet
	Enabled        bool       `json:"enabled"`
	Locked         bool       `json:"locked"`
	UnlockedAt     *time.Time `json:"unlocked_at,omitempty"`
	OwnerID        string     `json:"owner_id,omitempty"`
	Status         string     `json:"status,omitempty"` // ownership status: active, pending_approval
	DisplayName    string     `json:"display_name,omitempty"`
	Tags           []string   `json:"tags,omitempty"`
}

// ListWalletsResponse represents the response from listing wallets
type ListWalletsResponse struct {
	Wallets []WalletResponse `json:"wallets"`
	Total   int              `json:"total"`
	HasMore bool             `json:"has_more"`
}

// WalletSignersResponse represents the response from listing wallet's signers
type WalletSignersResponse struct {
	WalletID   string           `json:"wallet_id"`
	WalletType string           `json:"wallet_type"`
	Signers    []SignerResponse `json:"signers"`
	Total      int              `json:"total"`
	HasMore    bool             `json:"has_more"`
}

// UnlockSignerRequest represents the request to unlock a locked signer
type UnlockSignerRequest struct {
	// Rejected when empty: 400 "password is required" (signer_locking.go
	// handleUnlock, after the ownership check).
	Password string `json:"password" binding:"required"`
}

// ListSignersResponse represents the response for listing signers
type ListSignersResponse struct {
	Signers []SignerResponse `json:"signers"`
	Total   int              `json:"total"`
	HasMore bool             `json:"has_more"`
}

// CreateSignerRequest represents the request to create a signer
type CreateSignerRequest struct {
	// Rejected when empty: types.CreateSignerRequest.Validate answers
	// ErrMissingSignerType for the empty case, which the handler turns into 400.
	Type string `json:"type" binding:"required"`
	// ⚠️ NOT marked required although a keystore-type create cannot succeed
	// without it (ErrMissingKeystoreParams → 400): the requirement is
	// conditional on `type`, which a flat required list cannot express.
	Keystore    *CreateKeystoreRequest `json:"keystore,omitempty"`
	DisplayName string                 `json:"display_name,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
}

// CreateKeystoreRequest contains keystore creation parameters. Pick one
// import mode by populating exactly one field — leaving both empty creates
// a fresh keypair:
//   - PrivateKeyHex: raw secp256k1 (64 hex chars, 0x prefix optional).
//   - KeystoreJSON: full v3 keystore JSON encrypted with Password.
type CreateKeystoreRequest struct {
	// Required WHENEVER this object is present, which is exactly what a schema
	// `required` means: Validate answers ErrEmptyPassword → 400. There is no
	// path on which a present keystore object with an empty password succeeds.
	Password string `json:"password" binding:"required"`
	// ⛔ At most one of these two, and neither is required — leaving both empty
	// creates a fresh keypair. Sending both is 400 "specify private_key_hex or
	// keystore_json, not both". An at-most-one-of, which no required list says.
	PrivateKeyHex string `json:"private_key_hex,omitempty"`
	KeystoreJSON  string `json:"keystore_json,omitempty"`
}

// CreateSignerResponse represents the response after creating a signer
type CreateSignerResponse struct {
	Address     string   `json:"address"`
	Type        string   `json:"type"`
	Enabled     bool     `json:"enabled"`
	DisplayName string   `json:"display_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// PatchSignerLabelsRequest updates human-readable signer labels (owner only).
//
// ⛔ Neither field is required individually, but an empty body IS rejected (400
// "at least one of display_name or tags is required") — a one-of-two rule a flat
// required list cannot state. Both are pointers so "absent" and "set to empty"
// stay distinguishable, which is how a label gets cleared.
type PatchSignerLabelsRequest struct {
	DisplayName *string   `json:"display_name"`
	Tags        *[]string `json:"tags"`
}

// GrantAccessRequest represents the request to grant access to a signer.
type GrantAccessRequest struct {
	// Rejected when empty: 400 "api_key_id is required".
	APIKeyID string `json:"api_key_id" binding:"required"`
}

// SignerAccessResponse represents an access grant entry.
type SignerAccessResponse struct {
	APIKeyID  string    `json:"api_key_id"`
	GrantedBy string    `json:"granted_by"`
	CreatedAt time.Time `json:"created_at"`
}

// newSignerResponse builds an API response for a signer from its internal info.
func (h *SignerHandler) newSignerResponse(ctx context.Context, s types.SignerInfo) SignerResponse {
	resp := SignerResponse{
		Address:    s.Address,
		Type:       s.Type,
		Enabled:    s.Enabled,
		Locked:     s.Locked,
		UnlockedAt: s.UnlockedAt,
	}

	primaryAddress := s.Address
	if s.Type == string(types.SignerTypeHDWallet) {
		if hdwMgr, err := h.signerManager.HDWalletManager(); err == nil {
			found := false
			unlocked := false
			for _, wallet := range hdwMgr.ListHDWallets() {
				if strings.EqualFold(wallet.PrimaryAddress, s.Address) {
					primaryAddress = wallet.PrimaryAddress
					unlocked = !wallet.Locked
					found = true
					break
				}
				derived, derr := hdwMgr.ListDerivedAddresses(wallet.PrimaryAddress)
				if derr != nil {
					continue
				}
				for _, d := range derived {
					if strings.EqualFold(d.Address, s.Address) {
						primaryAddress = wallet.PrimaryAddress
						unlocked = !wallet.Locked
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				resp.Locked = !unlocked
				resp.Enabled = unlocked
			}
		}
	}

	// Fill HD hierarchy info if this is a derived address.
	// Keys from SignerManager.GetHDHierarchy match chain/evm.normalizeAddress (EIP-55), not lowercase hex.
	hierarchy := h.signerManager.GetHDHierarchy()
	if info, ok := hierarchy[common.HexToAddress(s.Address).Hex()]; ok {
		primaryAddress = info.ParentAddress
		resp.HDDerivationIndex = &info.DerivationIndex
	}
	// Get ownership: try current address first, fallback to primary address for derived addresses
	ownership, oErr := h.accessService.GetOwnership(ctx, s.Address)
	if oErr != nil && primaryAddress != "" && !strings.EqualFold(primaryAddress, s.Address) {
		ownership, oErr = h.accessService.GetOwnership(ctx, primaryAddress)
	}
	if oErr == nil && ownership != nil {
		resp.OwnerID = ownership.OwnerID
		resp.Status = string(ownership.Status)
		resp.DisplayName = ownership.DisplayName
		resp.Tags = ownership.Tags()
	}
	resp.PrimaryAddress = primaryAddress

	if h.signerRepo != nil {
		if rec, err := h.signerRepo.Get(ctx, s.Address); err == nil && rec != nil {
			if rec.PrimaryAddress != "" {
				resp.PrimaryAddress = rec.PrimaryAddress
			}
			resp.MaterialStatus = string(rec.MaterialStatus)
			resp.MaterialCheckedAt = rec.MaterialCheckedAt
			resp.MaterialMissingAt = rec.MaterialMissingAt
			resp.HDDerivationIndex = rec.HDDerivationIndex
			// Locked/Enabled deliberately not pulled from the DB record —
			// the SignerRegistry is the source of truth for live lock
			// state. The DB row is refreshed only on material_check ticks
			// (default 1h), so it lags reality between Unlock/Lock calls.
		}
	}
	if resp.PrimaryAddress == "" {
		resp.PrimaryAddress = s.Address
	}

	return resp
}
