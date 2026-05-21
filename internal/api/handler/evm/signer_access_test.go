package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// HTTP-level integration: a derived HD wallet address is reachable
// through POST /api/v1/evm/signers/{derived}/access when the caller
// owns the parent. Pre-fix this returned 403 "not the owner" because
// SignerAccessService.IsOwner only consulted the direct ownership row.
//
// Goes a step beyond the service unit test by exercising the real
// handler → service → repo wiring (real Gorm SQLite) and the JSON
// envelope, which is the layer where operators actually trip the bug.
func TestGrantAccess_HTTP_HDDerivedAddressResolvesParent(t *testing.T) {
	db := newSignerAccessTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	const (
		ownerID   = "owner-key"
		granteeID = "grantee-key"
		primary   = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		derived   = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	)
	mustCreateAPIKey(t, apiKeyRepo, ownerID, types.RoleAdmin)
	mustCreateAPIKey(t, apiKeyRepo, granteeID, types.RoleAgent)

	hdMgr := &mockHDWalletParentResolver{
		primaryAddrs: []string{primary},
		derived:      map[string][]types.SignerInfo{primary: {{Address: derived}}},
	}
	accessSvc, err := service.NewSignerAccessService(
		ownershipRepo, accessRepo, apiKeyRepo,
		func() (service.HDWalletParentResolver, error) { return hdMgr, nil },
		slog.Default(),
	)
	require.NoError(t, err)

	require.NoError(t, accessSvc.SetOwner(context.Background(), primary, ownerID, types.SignerOwnershipActive))

	h, err := NewSignerHandler(newSignerManagerWithAll(), accessSvc, slog.Default(), false)
	require.NoError(t, err)

	ownerKey := &types.APIKey{ID: ownerID, Name: "owner", Role: types.RoleAdmin, Enabled: true}

	// POST /api/v1/evm/signers/{derived}/access — must route through
	// HandleSignerAction (the address-subpath handler), not the
	// list/create dispatcher.
	body := map[string]string{"api_key_id": granteeID}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost, "/api/v1/evm/signers/"+derived+"/access", body, ownerKey)
	assert.Equal(t, http.StatusOK, rec.Code, "POST grant access on derived must succeed when parent owned, body=%s", rec.Body.String())

	// GET /api/v1/evm/signers/{derived}/access — derived address must
	// also resolve so the access list comes back to the same caller.
	recList := doActionRequest(t, h.HandleSignerAction, http.MethodGet, "/api/v1/evm/signers/"+derived+"/access", nil, ownerKey)
	require.Equal(t, http.StatusOK, recList.Code, "GET access list on derived must succeed: %s", recList.Body.String())
	var grants []SignerAccessResponse
	require.NoError(t, json.NewDecoder(recList.Body).Decode(&grants))
	require.Len(t, grants, 1)
	assert.Equal(t, granteeID, grants[0].APIKeyID)

	// Stranger gets 403 even on the derived address — fix must not
	// open access; only resolve identity-against-parent.
	strangerID := "stranger-key"
	mustCreateAPIKey(t, apiKeyRepo, strangerID, types.RoleAgent)
	stranger := &types.APIKey{ID: strangerID, Name: "stranger", Role: types.RoleAgent, Enabled: true}
	recForbid := doActionRequest(t, h.HandleSignerAction, http.MethodPost, "/api/v1/evm/signers/"+derived+"/access", body, stranger)
	assert.Equal(t, http.StatusForbidden, recForbid.Code)

	// DELETE round-trip closes the regression loop.
	recRevoke := doActionRequest(t, h.HandleSignerAction, http.MethodDelete, "/api/v1/evm/signers/"+derived+"/access/"+granteeID, nil, ownerKey)
	assert.Equal(t, http.StatusOK, recRevoke.Code, "DELETE on derived must succeed: %s", recRevoke.Body.String())
}

// --- Local helpers ---

func newSignerAccessTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.APIKey{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
	))
	return db
}

func mustCreateAPIKey(t *testing.T, repo storage.APIKeyRepository, id string, role types.APIKeyRole) {
	t.Helper()
	require.NoError(t, repo.Create(context.Background(), &types.APIKey{
		ID:        id,
		Name:      "Test " + id,
		Role:      role,
		Enabled:   true,
		Source:    types.APIKeySourceAPI,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))
}

// mockHDWalletParentResolver mirrors the service-layer mock so the
// handler test can wire a fake HD wallet tree without dragging in the
// full evmchain.HDWalletManager surface.
type mockHDWalletParentResolver struct {
	primaryAddrs []string
	derived      map[string][]types.SignerInfo
}

func (m *mockHDWalletParentResolver) ListPrimaryAddresses() []string { return m.primaryAddrs }
func (m *mockHDWalletParentResolver) ListDerivedAddresses(primary string) ([]types.SignerInfo, error) {
	return m.derived[primary], nil
}
