package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// --- Extended mock with function pointers for signer actions ---

type signerActionMock struct {
	signerMockSignerManager
	unlockFn func(ctx context.Context, address, password string) (*types.SignerInfo, error)
	lockFn   func(ctx context.Context, address string) (*types.SignerInfo, error)
	deleteFn func(ctx context.Context, address string) error
}

func (m *signerActionMock) UnlockSigner(ctx context.Context, address, password string) (*types.SignerInfo, error) {
	if m.unlockFn != nil {
		return m.unlockFn(ctx, address, password)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *signerActionMock) LockSigner(ctx context.Context, address string) (*types.SignerInfo, error) {
	if m.lockFn != nil {
		return m.lockFn(ctx, address)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *signerActionMock) DeleteSigner(ctx context.Context, address string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, address)
	}
	return fmt.Errorf("not implemented")
}

// --- Flexible ownership repo ---

type flexOwnershipRepo struct {
	signerStubOwnershipRepo
	owners map[string]string // address → ownerID
}

func (r *flexOwnershipRepo) Get(_ context.Context, address string) (*types.SignerOwnership, error) {
	if ownerID, ok := r.owners[address]; ok {
		return &types.SignerOwnership{
			SignerAddress: address,
			OwnerID:       ownerID,
			Status:        types.SignerOwnershipActive,
		}, nil
	}
	return nil, types.ErrNotFound
}

func newFlexAccessService(t *testing.T, owners map[string]string) *service.SignerAccessService {
	t.Helper()
	svc, err := service.NewSignerAccessService(
		&flexOwnershipRepo{owners: owners},
		&signerStubAccessRepo{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)
	return svc
}

// --- Helper ---

const testAddr = "0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd"
const testKeyID = "test-owner-key"

func testOwnerAPIKey() *types.APIKey {
	return &types.APIKey{ID: testKeyID, Name: "Test Owner", Role: "admin", Enabled: true}
}

func testOtherAPIKey() *types.APIKey {
	return &types.APIKey{ID: "other-key", Name: "Other User", Role: "dev", Enabled: true}
}

func doActionRequest(t *testing.T, handler http.HandlerFunc, method, path string, body interface{}, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(data)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func newActionHandler(t *testing.T, mgr *signerActionMock, owners map[string]string) *SignerHandler {
	t.Helper()
	accessSvc := newFlexAccessService(t, owners)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), nil)
	require.NoError(t, err)
	return h
}

// --- HandleSignerAction tests ---

func TestHandleSignerAction_Unauthorized(t *testing.T) {
	mgr := &signerActionMock{}
	h := newActionHandler(t, mgr, nil)
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleSignerAction_InvalidPath(t *testing.T) {
	mgr := &signerActionMock{}
	h := newActionHandler(t, mgr, nil)
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleSignerAction_UnknownAction(t *testing.T) {
	mgr := &signerActionMock{}
	h := newActionHandler(t, mgr, nil)
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/foobar", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "unknown action")
}

// --- Unlock tests ---

func TestHandleUnlock_Success(t *testing.T) {
	mgr := &signerActionMock{
		unlockFn: func(_ context.Context, addr, _ string) (*types.SignerInfo, error) {
			return &types.SignerInfo{Address: addr, Type: "keystore", Enabled: true}, nil
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]string{"password": "secret123"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleUnlock_NotOwner_NotFound(t *testing.T) {
	mgr := &signerActionMock{}
	// No ownership record → 404
	h := newActionHandler(t, mgr, nil)

	body := map[string]string{"password": "secret123"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOtherAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleUnlock_NotOwner_Forbidden(t *testing.T) {
	mgr := &signerActionMock{}
	// Ownership exists but for different key → 403
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]string{"password": "secret123"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOtherAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleUnlock_MissingPassword(t *testing.T) {
	mgr := &signerActionMock{}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]string{"password": ""}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleUnlock_MethodNotAllowed was removed: its route is method-scoped now (see setupRoutes) and Go's
// ServeMux answers 405 before the handler runs. A test that calls the handler
// directly with the wrong method asserts a check this layer no longer owns —
// and should not own, since the mux cannot forget it.

// --- Lock tests ---

func TestHandleLock_Success(t *testing.T) {
	mgr := &signerActionMock{
		lockFn: func(_ context.Context, addr string) (*types.SignerInfo, error) {
			return &types.SignerInfo{Address: addr, Type: "keystore", Enabled: true, Locked: true}, nil
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/lock", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleLock_NotOwner(t *testing.T) {
	mgr := &signerActionMock{}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/lock", nil, testOtherAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- Approve tests ---

// TestHandleApprove_MethodNotAllowed was removed: its route is method-scoped now (see setupRoutes) and Go's
// ServeMux answers 405 before the handler runs. A test that calls the handler
// directly with the wrong method asserts a check this layer no longer owns —
// and should not own, since the mux cannot forget it.

// --- Transfer tests ---

// TestHandleTransfer_MethodNotAllowed was removed: its route is method-scoped now (see setupRoutes) and Go's
// ServeMux answers 405 before the handler runs. A test that calls the handler
// directly with the wrong method asserts a check this layer no longer owns —
// and should not own, since the mux cannot forget it.

// --- Delete tests ---

func TestHandleDelete_Success(t *testing.T) {
	mgr := &signerActionMock{
		deleteFn: func(_ context.Context, _ string) error { return nil },
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHandleDelete_NotOwner(t *testing.T) {
	mgr := &signerActionMock{}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOtherAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleSignerAction_StateChangeRequiresPost is a regression test for a
// defect found on 2026-09-10 while decomposing routes.
//
// ⛔ What was wrong: HandleSignerAction carried a comment asserting that each
// of the four state-changing actions has its own
// `POST /api/v1/evm/signers/{address}/<action>` route, "so the mux answers 405
// before this switch runs". Go's ServeMux answers 405 only when a pattern
// matches the path and *no* pattern matches the method. `/api/v1/evm/signers/`
// is registered without a method, so it matches every method — there is always
// a match and 405 never happens. A GET to .../unlock fell through to this
// handler, which read the action out of the path and unlocked the signer. None
// of the four action handlers checks r.Method either.
//
// ⚠️ Asserting the status code alone would be a weak test: a handler that
// mutates and *then* writes 405 would pass it. So each case asserts the manager
// function was never called — the mutation must not happen at all.
//
// ⭐ The structural fix is the decomposition (proposal S5): with no method-less
// prefix left, an unroutable verb cannot reach a handler. This test should
// survive that and keep passing.
func TestHandleSignerAction_StateChangeRequiresPost(t *testing.T) {
	for _, action := range []string{"unlock", "lock", "approve", "transfer"} {
		for _, method := range []string{
			http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodPatch,
		} {
			t.Run(method+" "+action, func(t *testing.T) {
				called := false
				mgr := &signerActionMock{
					unlockFn: func(_ context.Context, addr, _ string) (*types.SignerInfo, error) {
						called = true
						return &types.SignerInfo{Address: addr}, nil
					},
					lockFn: func(_ context.Context, addr string) (*types.SignerInfo, error) {
						called = true
						return &types.SignerInfo{Address: addr}, nil
					},
				}
				h := newActionHandler(t, mgr, map[string]string{testAddr: testKeyID})

				rec := doActionRequest(t, h.HandleSignerAction, method,
					"/api/v1/evm/signers/"+testAddr+"/"+action,
					map[string]string{"password": "secret123", "new_owner_id": "someone-else"},
					testOwnerAPIKey())

				assert.Equal(t, http.StatusMethodNotAllowed, rec.Code,
					"%s on a state-changing action must be refused; only POST performs it", method)
				assert.False(t, called,
					"⛔ %s %s reached the signer manager — the state change happened. "+
						"Refusing after mutating is not refusing.", method, action)
			})
		}
	}
}

// TestHandleSignerAction_PostStillWorks is the other half: the guard must not
// have broken the verb that is supposed to work. Without this, deleting the
// four actions outright would also make the test above pass.
func TestHandleSignerAction_PostStillWorks(t *testing.T) {
	called := false
	mgr := &signerActionMock{
		unlockFn: func(_ context.Context, addr, _ string) (*types.SignerInfo, error) {
			called = true
			return &types.SignerInfo{Address: addr, Type: "keystore", Enabled: true}, nil
		},
	}
	h := newActionHandler(t, mgr, map[string]string{testAddr: testKeyID})

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock",
		map[string]string{"password": "secret123"}, testOwnerAPIKey())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, called, "POST must still perform the unlock")
}
