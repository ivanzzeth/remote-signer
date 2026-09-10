package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

// callSigner invokes one signer endpoint function on a request the caller
// built, after filling in the wildcards a matching route pattern would have
// filled in.
//
// ⚠️ It is NOT a dispatcher and must not become one. The endpoint is named at
// the call site — that is the point of the decomposition, and it is what makes
// these tests say which endpoint they are about. All this does is populate
// {address} and {keyID}, which httptest.NewRequest cannot know about because no
// mux matched. Routing itself is asserted in signer_routes_test.go against the
// production patterns; nothing here proves a path reaches a handler.
//
// ⛔ Deriving the values from the URL rather than taking them as arguments is
// deliberate: every call site already spells the address inside the path
// expression, and a second copy is a place for the two to disagree.
func callSigner(fn http.HandlerFunc, rec *httptest.ResponseRecorder, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/api/v1/evm/signers/")
	parts := strings.Split(rest, "/")
	if parts[0] != "" {
		req.SetPathValue("address", parts[0])
	}
	if len(parts) >= 3 && parts[1] == "access" {
		req.SetPathValue("keyID", parts[2])
	}
	fn(rec, req)
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
	callSigner(handler, rec, req)
	return rec
}

func newActionHandler(t *testing.T, mgr *signerActionMock, owners map[string]string) *SignerHandler {
	t.Helper()
	accessSvc := newFlexAccessService(t, owners)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), nil)
	require.NoError(t, err)
	return h
}

// --- Signer endpoint tests ---

// TestSignerEndpoint_Unauthorized was TestHandleSignerAction_Unauthorized.
// ⚠️ Renamed, not weakened: the 401 it pins was the first thing
// HandleSignerAction did and is now the first thing every signer endpoint does
// (requireAPIKey), so the name had to stop referring to a function that no
// longer exists. Still the same request, the same nil key, the same assertion.
func TestSignerEndpoint_Unauthorized(t *testing.T) {
	mgr := &signerActionMock{}
	h := newActionHandler(t, mgr, nil)
	rec := doActionRequest(t, h.Unlock, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ⚠️ TestHandleSignerAction_InvalidPath and TestHandleSignerAction_UnknownAction
// moved to signer_routes_test.go as TestSignerRoutes_UnclaimedPathsReachNoHandler.
// Both asserted HandleSignerAction's own path parsing — "/api/v1/evm/signers/"
// with no address answered 400, and ".../{address}/foobar" answered 400 "unknown
// action: foobar". Neither string can be produced any more: no route claims
// those paths, so the question "what does the handler say about them" was
// replaced by the stronger "which handler do they reach", answered against the
// production patterns. ⛔ They were not deleted; the property is asserted in the
// form the routes give it.

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
	rec := doActionRequest(t, h.Unlock, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleUnlock_NotOwner_NotFound(t *testing.T) {
	mgr := &signerActionMock{}
	// No ownership record → 404
	h := newActionHandler(t, mgr, nil)

	body := map[string]string{"password": "secret123"}
	rec := doActionRequest(t, h.Unlock, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOtherAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleUnlock_NotOwner_Forbidden(t *testing.T) {
	mgr := &signerActionMock{}
	// Ownership exists but for different key → 403
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]string{"password": "secret123"}
	rec := doActionRequest(t, h.Unlock, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOtherAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleUnlock_MissingPassword(t *testing.T) {
	mgr := &signerActionMock{}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]string{"password": ""}
	rec := doActionRequest(t, h.Unlock, http.MethodPost,
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

	rec := doActionRequest(t, h.Lock, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/lock", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleLock_NotOwner(t *testing.T) {
	mgr := &signerActionMock{}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.Lock, http.MethodPost,
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

	rec := doActionRequest(t, h.DeleteSigner, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHandleDelete_NotOwner(t *testing.T) {
	mgr := &signerActionMock{}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.DeleteSigner, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOtherAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ⚠️ TestHandleSignerAction_StateChangeRequiresPost and
// TestHandleSignerAction_PostStillWorks — the regression pair for the 6d30ba1
// defect, where `GET .../{address}/unlock` and `DELETE .../{address}/approve`
// actually unlocked and approved — moved to signer_routes_test.go as
// TestSignerRoutes_StateChangeRequiresPost and
// TestSignerRoutes_PostStillPerformsTheAction.
//
// ⛔ They could not stay here and could not be deleted. They asserted the guard
// HandleSignerAction carried; the decomposition removes both the guard and the
// function, because the rule is now stated where the mux enforces it — the four
// actions are POST-only patterns and nothing else claims their paths. A test
// that called an endpoint function directly with a GET would be asserting a
// check this layer no longer owns *and should not own*, since the mux cannot
// forget it. So the pair was rewritten to drive the production patterns from
// internal/api/module_signers.go, and it still asserts what mattered most: the
// signer manager was never called. Refusing after mutating is not refusing.
//
// ⚠️ Both halves are still there, and still paired for the same reason: without
// the "POST still works" half, deleting the four actions outright would make
// the first one pass.
