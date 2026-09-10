// Package handler_test — this file holds the API-key handler's route-level
// tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S4)
//
// S4 splits APIKeyHandler into one function per method and sub-path and moves it
// onto r.PathValue. The tests below drive those endpoints, and after the split
// an endpoint is reachable only through the route that names it — so driving
// them means going through internal/api's route registration.
//
// ⛔ The tempting way to do that — build an http.ServeMux in the fixture and
// register "/api/v1/api-keys" and "/api/v1/api-keys/" by hand — creates a second
// source of truth for the route table. It drifts from the production
// registration silently: the tests stay green while exercising routes the daemon
// does not serve. So the patterns come from api.apiKeysModule's Routes(),
// reached through the exported api.Module / api.RouteRegistrar pair.
//
// ⚠️ Which is why this is `package handler_test`: internal/api imports
// internal/api/handler, so an in-package test file cannot import internal/api
// back — that is an import cycle. The cost is that these tests can only use
// exported identifiers; the API-key DTOs already were, and the shared mock
// repository is exported from apikey_test.go for this (see the note there).
//
// ⚠️ Three API-key tests did NOT move: TestCoverage_UpdateAPIKey_* and
// TestCoverage_DeleteAPIKey_* in coverage_boost_test.go call unexported methods
// (h.updateAPIKey) and so cannot leave package handler. They call the endpoint
// function with an explicit path value instead.
//
// ⚠️ What these tests still do NOT exercise: the middleware chain. Five of the
// six routes register as Permitted(PermManageAPIKeys), whose chain begins with
// AuthMiddleware, which refuses any request lacking X-API-Key-ID / X-Timestamp /
// X-Signature (middleware/auth.go:62-69). Every test below injects its API key
// through the request context instead, as they always have. So the test
// registrar drops the RouteAuth it is handed and registers the bare handler:
// what moved is dispatch, and nothing here asserts anything about authorization.
// ⛔ Do not read a green run as evidence that an API-key route is correctly
// permissioned — that lives in the archcheck route-auth gates and their
// baselines, and in the pattern assertion below.
package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------- the registrar ----------
//
// ⚠️ Named apiKey* rather than reusing the wallet family's muxRegistrar /
// recordingRegistrar: those live in wallet_routes_test.go behind
// `//go:build integration`, in this same external package, so under that tag the
// two files compile together and a shared name would be a redeclaration. Same
// shape, different name.

type apiKeyMuxRegistrar struct{ mux *http.ServeMux }

func (m apiKeyMuxRegistrar) Handle(pattern string, _ api.RouteAuth, h http.Handler) {
	m.mux.Handle(pattern, h)
}

type apiKeyRecordingRegistrar struct {
	record func(pattern string, auth api.RouteAuth)
}

func (r apiKeyRecordingRegistrar) Handle(pattern string, auth api.RouteAuth, _ http.Handler) {
	r.record(pattern, auth)
}

// apiKeyMux registers the production API-key routes over an otherwise empty mux.
//
// ⭐ An empty mux is deliberate: a path no API-key pattern claims must reach
// nothing at all, which is exactly the property direct h.ServeHTTP dispatch
// could not have. TestAPIKeyRoutes_UnclaimedPathNoLongerReachesTheHandler pins
// it.
func apiKeyMux(t *testing.T, h *handler.APIKeyHandler) http.Handler {
	t.Helper()
	mod, err := api.NewAPIKeysModule(h)
	require.NoError(t, err)
	require.NotNil(t, mod, "no module means no pattern would be registered, and every request below "+
		"would 404 for a reason that has nothing to do with what is under test")

	mux := http.NewServeMux()
	mod.Routes(apiKeyMuxRegistrar{mux: mux})
	return mux
}

// doAPIKeyCollectionRequest replaces the two helpers this file used to have —
// doAPIKeyWalletRequest, which called h.ServeHTTP, and doAPIKeyItemRequest,
// which called h.ServeKeyHTTP. ⭐ That there is one of them now, and that it
// takes no hint about which endpoint it means, IS the change: the mux decides
// from the method and the path, exactly as it does in the daemon.
func doAPIKeyCollectionRequest(t *testing.T, mux http.Handler, method, path string, body any, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewBuffer(b)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestAPIKeyRoutes_RegistersExactlyTheProductionPatterns is the one assertion
// that would notice the harness quietly registering nothing, or registering
// something else. ⚠️ It does not say these patterns are *right* — it says the
// mux the tests below drive is the mux apiKeysModule builds, which is the only
// reason a green run here means anything about the daemon.
//
// ⛔ Its more important half is the authorization column. Splitting two prefixes
// into five endpoints is exactly the moment a reviewer's eye slides past
// `Permitted(PermManageAPIKeys)` on the GET routes and someone "improves" one to
// a read permission or to AuthenticatedOnly — and the API-key surface is the one
// where that is worst, since /names already exists precisely to be the weaker
// read the UI needs. Nothing else in the API-key family would notice: the test
// registrar drops the RouteAuth entirely, so not one test below runs the
// middleware chain. The /names exemption's full reason string is compared, not
// just its shape, so weakening the reason fails here too.
func TestAPIKeyRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	h, err := handler.NewAPIKeyHandler(handler.NewMockAPIKeyRepo(), handler.ApikeyLogger(), nil)
	require.NoError(t, err)
	mod, err := api.NewAPIKeysModule(h)
	require.NoError(t, err)
	require.NotNil(t, mod)

	const namesExemption = `authenticated-only("deliberately weaker than the PermManageAPIKeys surface it sits inside, and the callers are known: ` +
		`the Web UI resolves its own key's role through it (web/src/lib/rbac.ts:8-11) and the extension ` +
		`fills the grant-access and signer-filter dropdowns (extension/background.js:2680-2692) — both from ` +
		`keys that are not the caller's. The projection is id+name+role+enabled over enabled keys only ` +
		`(handler/apikey.go:231-254) — no public key, no material, no ability to mutate. ` +
		`⚠️ It does disclose the roster of key names and roles to any authenticated key; that is the ` +
		`trade this route was created to make, and it is the one to revisit first if it turns out to be wrong.")`

	var got []string
	mod.Routes(apiKeyRecordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got = append(got, pattern+" → "+auth.String())
	}})

	// ⚠️ Order is the registration order, not sorted: a module registering the
	// same set in a different order is a different edit and worth seeing.
	// ⭐ /names is first because it was first in router.go, not because the mux
	// needs it to be — a literal segment beats a wildcard whatever the order,
	// which TestAPIKeyRoutes_NamesBeatsTheIDWildcard measures.
	assert.Equal(t, []string{
		"GET /api/v1/api-keys/names → " + namesExemption,
		"GET /api/v1/api-keys → permitted(manage_api_keys)",
		"POST /api/v1/api-keys → permitted(manage_api_keys)",
		"GET /api/v1/api-keys/{id} → permitted(manage_api_keys)",
		"PUT /api/v1/api-keys/{id} → permitted(manage_api_keys)",
		"DELETE /api/v1/api-keys/{id} → permitted(manage_api_keys)",
	}, got)
	assert.Equal(t, "api-keys", mod.Name())
}

// TestAPIKeyRoutes_NamesBeatsTheIDWildcard replaces a claim that used to be a
// comment at the registration site: that GET /api/v1/api-keys/names "must land
// BEFORE the /api/v1/api-keys/ prefix so the standard mux's longest-match wins".
// ⛔ That was true of the pre-1.22 mux. With method+wildcard patterns Go picks
// the more specific pattern regardless of registration order, so the claim is
// now both unnecessary and untested — this measures the property the comment was
// worried about instead of asserting the ordering that used to imply it.
func TestAPIKeyRoutes_NamesBeatsTheIDWildcard(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.Seed(handler.MakeTestAPIKey("names", "A key literally called names", types.APIKeySourceAPI, true))
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys/names", nil, handler.ApikeyAdminKey())
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"keys"`)
	assert.NotContains(t, rr.Body.String(), `"rate_limit"`,
		"the projection answered, not the {id} route — a full APIKeyResponse would carry rate_limit")
}

// TestAPIKeyRoutes_UnclaimedPathNoLongerReachesTheHandler is the evidence that
// the move actually changed something, run as a controlled pair: the same
// request dispatched directly at the endpoint function and dispatched through
// the mux.
//
// ⭐ The list endpoint never looks at the path at all, so called directly it
// answers 200 with a listing for *any* path whatsoever. That is what every test
// in this file was doing before the move: asserting a status code the URL had no
// influence over. Through the mux the same request reaches nothing.
//
// ⚠️ The `direct` arm is the control, not the harness. Delete it and this test
// degrades to "a 404 came back", which a mux with no routes at all would also
// satisfy.
func TestAPIKeyRoutes_UnclaimedPathNoLongerReachesTheHandler(t *testing.T) {
	const unclaimed = "/api/v1/api-keys-archive"

	h, err := handler.NewAPIKeyHandler(handler.NewMockAPIKeyRepo(), handler.ApikeyLogger(), nil)
	require.NoError(t, err)
	mux := apiKeyMux(t, h)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, unclaimed, nil)
		return req.WithContext(context.WithValue(context.Background(),
			middleware.APIKeyContextKey, handler.ApikeyAdminKey()))
	}

	direct := httptest.NewRecorder()
	h.ListAPIKeys(direct, newReq())
	require.Equal(t, http.StatusOK, direct.Code,
		"premise of this test: called directly, the handler serves %s as though it were /api/v1/api-keys. "+
			"If that stops being true the control arm is gone and the routed arm proves nothing on its own", unclaimed)
	require.Contains(t, direct.Body.String(), `"keys"`)

	routed := httptest.NewRecorder()
	mux.ServeHTTP(routed, newReq())
	assert.Equal(t, http.StatusNotFound, routed.Code,
		"%s is claimed by no API-key pattern, so it must reach no API-key handler", unclaimed)
	assert.NotContains(t, routed.Body.String(), `"keys"`,
		"the mux answered, but with the handler's listing — a pattern is claiming more than it should")
}

func TestNewAPIKeyHandler(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	logger := handler.ApikeyLogger()

	t.Run("valid_args", func(t *testing.T) {
		h, err := handler.NewAPIKeyHandler(repo, logger, nil)
		require.NoError(t, err)
		assert.NotNil(t, h)
	})

	t.Run("nil_repo_returns_error", func(t *testing.T) {
		_, err := handler.NewAPIKeyHandler(nil, logger, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "API key repository is required")
	})

	t.Run("nil_logger_returns_error", func(t *testing.T) {
		_, err := handler.NewAPIKeyHandler(repo, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_List_Success(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.Seed(handler.MakeTestAPIKey("key-1", "Key One", types.APIKeySourceAPI, true))
	repo.Seed(handler.MakeTestAPIKey("key-2", "Key Two", types.APIKeySourceConfig, true))

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp handler.ListAPIKeysResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Total)
	assert.Equal(t, 2, len(resp.Keys))

	// Verify response fields are populated
	for _, k := range resp.Keys {
		assert.NotEmpty(t, k.ID)
		assert.NotEmpty(t, k.Name)
		assert.NotEmpty(t, k.Source)
	}
}

func TestAPIKeyHandler_List_WithSourceFilter(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.Seed(handler.MakeTestAPIKey("key-api-1", "API Key", types.APIKeySourceAPI, true))
	repo.Seed(handler.MakeTestAPIKey("key-cfg-1", "Config Key", types.APIKeySourceConfig, true))

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys?source=api", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp handler.ListAPIKeysResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, len(resp.Keys))
	assert.Equal(t, "api", resp.Keys[0].Source)
}

func TestAPIKeyHandler_List_WithEnabledFilter(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.Seed(handler.MakeTestAPIKey("key-en", "Enabled Key", types.APIKeySourceAPI, true))
	repo.Seed(handler.MakeTestAPIKey("key-dis", "Disabled Key", types.APIKeySourceAPI, false))

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys?enabled=true", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp handler.ListAPIKeysResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, len(resp.Keys))
	assert.True(t, resp.Keys[0].Enabled)
}

func TestAPIKeyHandler_List_InvalidEnabledParam(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys?enabled=notbool", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "invalid enabled parameter")
}

func TestAPIKeyHandler_List_InvalidLimitParam(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys?limit=abc", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "invalid limit parameter")
}

func TestAPIKeyHandler_List_NegativeLimitParam(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys?limit=-1", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAPIKeyHandler_List_LimitClamping(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	// Track the filter passed to List
	var capturedFilter storage.APIKeyFilter
	repo.ListFn = func(_ context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error) {
		capturedFilter = filter
		return nil, nil
	}
	repo.CountFn = func(_ context.Context, filter storage.APIKeyFilter) (int, error) {
		return 0, nil
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys?limit=500", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)
	// limit > 100 should be clamped to 100
	assert.Equal(t, 100, capturedFilter.Limit)
}

func TestAPIKeyHandler_List_InvalidOffsetParam(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys?offset=abc", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAPIKeyHandler_List_NegativeOffsetParam(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys?offset=-5", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAPIKeyHandler_List_Error(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.ListFn = func(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
		return nil, fmt.Errorf("database connection lost")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to list API keys")
}

func TestAPIKeyHandler_List_CountError(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.CountFn = func(_ context.Context, _ storage.APIKeyFilter) (int, error) {
		return 0, fmt.Errorf("count query timeout")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to count API keys")
}

func TestAPIKeyHandler_List_Empty(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp handler.ListAPIKeysResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 0, resp.Total)
	assert.NotNil(t, resp.Keys)
	assert.Equal(t, 0, len(resp.Keys))
}

// ---------------------------------------------------------------------------
// Tests: Get
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Get_Success(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("key-get-1", "Get Key", types.APIKeySourceAPI, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys/key-get-1", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp handler.APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "key-get-1", resp.ID)
	assert.Equal(t, "Get Key", resp.Name)
	assert.Equal(t, "api", resp.Source)
	assert.True(t, resp.Enabled)
}

func TestAPIKeyHandler_Get_NotFound(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys/nonexistent", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "API key not found", errResp["error"])
}

func TestAPIKeyHandler_Get_InternalError(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.GetFn = func(_ context.Context, _ string) (*types.APIKey, error) {
		return nil, fmt.Errorf("database error")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys/key-1", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAPIKeyHandler_Get_NoPublicKey(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("key-nopub", "No Pub Key", types.APIKeySourceAPI, true)
	key.PublicKeyHex = "secret_public_key_hex_value"
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys/key-nopub", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify public_key is NOT in the response body
	bodyBytes := rr.Body.Bytes()
	assert.NotContains(t, string(bodyBytes), "public_key")
	assert.NotContains(t, string(bodyBytes), "secret_public_key_hex_value")
}

// TestAPIKeyHandler_Get_EmptyID_NoLongerReachesTheHandler replaces
// TestAPIKeyHandler_Get_EmptyID, and the rename records a deliberate change.
//
// ⛔ Client-visible: GET /api/v1/api-keys/ used to answer
// 400 {"error":"API key ID is required"} — a guard that only existed because a
// prefix pattern let a request with no id reach the handler at all. A {id}
// wildcard does not match an empty segment (measured), so nothing reaches the
// handler and the answer is 404: this bare mux's plain-text one here, the
// /api/v1/ fallback's JSON one in a daemon.
//
// ⚠️ The test is rewritten rather than deleted because it is the only place the
// repo says out loud what that URL does.
func TestAPIKeyHandler_Get_EmptyID_NoLongerReachesTheHandler(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	// Path with no ID after prefix
	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodGet, "/api/v1/api-keys/", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.NotContains(t, rr.Body.String(), "API key ID is required",
		"the handler answered — some pattern is still claiming a path with no id in it")
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Create_Success(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "my-new-key",
		Name:      "My New Key",
		PublicKey: "abcdef1234567890abcdef1234567890",
		Role:      "strategy",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp handler.APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "my-new-key", resp.ID)
	assert.Equal(t, "My New Key", resp.Name)
	assert.Equal(t, types.APIKeySourceAPI, resp.Source)
	assert.True(t, resp.Enabled)
	assert.Equal(t, 100, resp.RateLimit) // default rate limit

	// Verify key is stored
	stored, storeErr := repo.Get(context.Background(), "my-new-key")
	require.NoError(t, storeErr)
	assert.Equal(t, types.APIKeySourceAPI, stored.Source)
}

func TestAPIKeyHandler_Create_WithCustomRateLimit(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "rate-key",
		Name:      "Rate Key",
		PublicKey: "abcdef",
		Role:      "admin",
		RateLimit: 50,
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp handler.APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 50, resp.RateLimit)
}

func TestAPIKeyHandler_Create_ReadOnly(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), func() bool { return true }) // readOnly=true
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "should-fail",
		Name:      "Should Fail",
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "API key management is disabled")
}

func TestAPIKeyHandler_Create_InvalidID_Empty(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "",
		Name:      "Empty ID",
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "id is required", errResp["error"])
}

func TestAPIKeyHandler_Create_InvalidID_TooLong(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	longID := strings.Repeat("a", 65)
	reqBody := handler.CreateAPIKeyRequest{
		ID:        longID,
		Name:      "Too Long ID",
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "at most 64 characters")
}

func TestAPIKeyHandler_Create_InvalidID_SpecialChars(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	badIDs := []string{"key with spaces", "key@special", "key/slash", "key.dot", "key_underscore"}
	for _, id := range badIDs {
		t.Run(id, func(t *testing.T) {
			reqBody := handler.CreateAPIKeyRequest{
				ID:        id,
				Name:      "Bad ID",
				PublicKey: "abcdef",
			}

			rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
			assert.Equal(t, http.StatusBadRequest, rr.Code)

			var errResp map[string]string
			require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
			assert.Contains(t, errResp["error"], "alphanumeric characters and hyphens")
		})
	}
}

func TestAPIKeyHandler_Create_ValidIDWithHyphens(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "my-key-123",
		Name:      "Hyphen Key",
		PublicKey: "abcdef",
		Role:      "admin",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestAPIKeyHandler_Create_MissingName(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "valid-id",
		Name:      "",
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "name is required", errResp["error"])
}

func TestAPIKeyHandler_Create_NameTooLong(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "valid-id",
		Name:      strings.Repeat("n", 256),
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "at most 255 characters")
}

func TestAPIKeyHandler_Create_MissingPublicKey(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "valid-id",
		Name:      "Valid Name",
		PublicKey: "",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "public_key is required", errResp["error"])
}

func TestAPIKeyHandler_Create_DuplicateID(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.Seed(handler.MakeTestAPIKey("dup-key", "Existing", types.APIKeySourceAPI, true))

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "dup-key",
		Name:      "Duplicate",
		PublicKey: "abcdef",
		Role:      "admin",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to create API key")
}

func TestAPIKeyHandler_Create_InvalidJSON(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewBufferString("{broken json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, handler.ApikeyAdminKey()))

	rr := httptest.NewRecorder()
	apiKeyMux(t, h).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "invalid request body")
}

func TestAPIKeyHandler_Create_MethodNotAllowed(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	// ⚠️ The status is unchanged and the body is not: 405 used to be the
	// handler's own JSON envelope, and it is now the mux's plain text, because
	// the method is decided at the route. ⛔ And in a daemon it is not a 405 at
	// all — "/api/v1/" matches every method, so the request reaches the JSON-404
	// fallback (proposal §0 correction 9). Nothing in this package can see that;
	// the fallback is registered by the router, not by the module.
	assert.NotContains(t, rr.Body.String(), `"error"`,
		"a JSON envelope here means the handler decided the method again, which the route now does")
}

func TestAPIKeyHandler_Create_RepoGetFailsAfterCreate(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	callCount := 0
	repo.GetFn = func(_ context.Context, id string) (*types.APIKey, error) {
		callCount++
		// First call during create's re-fetch fails
		return nil, fmt.Errorf("transient error")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "get-fail-key",
		Name:      "Get Fail Key",
		PublicKey: "abcdef",
		Role:      "admin",
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	// Should still return 201 even if re-fetch fails
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp handler.APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "get-fail-key", resp.ID)
}

// ---------------------------------------------------------------------------
// Tests: Update
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Update_Success(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("upd-key", "Original", types.APIKeySourceAPI, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	newName := "Updated Name"
	newEnabled := false
	newRateLimit := 50
	reqBody := handler.UpdateAPIKeyRequest{
		Name:      &newName,
		Enabled:   &newEnabled,
		RateLimit: &newRateLimit,
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/upd-key", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp handler.APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "Updated Name", resp.Name)
	assert.False(t, resp.Enabled)
	assert.Equal(t, 50, resp.RateLimit)
}

func TestAPIKeyHandler_Update_AllFields(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("upd-all", "Original", types.APIKeySourceAPI, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	newName := "All Updated"
	newEnabled := false
	newRole := "admin"
	newRateLimit := 200
	reqBody := handler.UpdateAPIKeyRequest{
		Name:      &newName,
		Enabled:   &newEnabled,
		Role:      &newRole,
		RateLimit: &newRateLimit,
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/upd-all", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp handler.APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "All Updated", resp.Name)
	assert.False(t, resp.Enabled)
	assert.Equal(t, types.RoleAdmin, resp.Role)
	assert.Equal(t, 200, resp.RateLimit)
}

func TestAPIKeyHandler_Update_ReadOnly(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), func() bool { return true })
	require.NoError(t, err)

	newName := "Updated"
	reqBody := handler.UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/some-key", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "API key management is disabled")
}

func TestAPIKeyHandler_Update_ConfigSource(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("cfg-key", "Config Key", types.APIKeySourceConfig, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	newName := "Updated"
	reqBody := handler.UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/cfg-key", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "cannot modify config-sourced API key")
}

func TestAPIKeyHandler_Update_NotFound(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	newName := "Updated"
	reqBody := handler.UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/nonexistent", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAPIKeyHandler_Update_InternalGetError(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.GetFn = func(_ context.Context, _ string) (*types.APIKey, error) {
		return nil, fmt.Errorf("database error")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	newName := "Updated"
	reqBody := handler.UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/some-key", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAPIKeyHandler_Update_InvalidJSON(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("bad-json-key", "Bad JSON Key", types.APIKeySourceAPI, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/api-keys/bad-json-key", bytes.NewBufferString("{broken"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, handler.ApikeyAdminKey()))

	rr := httptest.NewRecorder()
	apiKeyMux(t, h).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "invalid request body")
}

func TestAPIKeyHandler_Update_EmptyName(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("empty-name-key", "Original", types.APIKeySourceAPI, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	emptyName := ""
	reqBody := handler.UpdateAPIKeyRequest{Name: &emptyName}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/empty-name-key", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "name must not be empty")
}

func TestAPIKeyHandler_Update_NameTooLong(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("long-name-key", "Original", types.APIKeySourceAPI, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	longName := strings.Repeat("n", 256)
	reqBody := handler.UpdateAPIKeyRequest{Name: &longName}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/long-name-key", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "at most 255 characters")
}

func TestAPIKeyHandler_Update_RepoUpdateError(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("upd-err-key", "Update Err Key", types.APIKeySourceAPI, true)
	repo.Seed(key)
	repo.UpdateFn = func(_ context.Context, _ *types.APIKey) error {
		return fmt.Errorf("constraint violation")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	newName := "New Name"
	reqBody := handler.UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/upd-err-key", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to update API key")
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Delete_Success(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("del-key", "Delete Key", types.APIKeySourceAPI, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/del-key", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify key is gone
	_, getErr := repo.Get(context.Background(), "del-key")
	assert.ErrorIs(t, getErr, types.ErrNotFound)
}

func TestAPIKeyHandler_Delete_ReadOnly(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), func() bool { return true })
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/some-key", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "API key management is disabled")
}

func TestAPIKeyHandler_Delete_ConfigSource(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("cfg-del-key", "Config Key", types.APIKeySourceConfig, true)
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/cfg-del-key", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "cannot delete config-sourced API key")
}

func TestAPIKeyHandler_Delete_NotFound(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/nonexistent", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAPIKeyHandler_Delete_InternalGetError(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.GetFn = func(_ context.Context, _ string) (*types.APIKey, error) {
		return nil, fmt.Errorf("database error")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/some-key", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAPIKeyHandler_Delete_RepoDeleteError(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("del-err-key", "Delete Err Key", types.APIKeySourceAPI, true)
	repo.Seed(key)
	repo.DeleteFn = func(_ context.Context, _ string) error {
		return fmt.Errorf("foreign key constraint")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/del-err-key", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to delete API key")
}

func TestAPIKeyHandler_Delete_RepoDeleteNotFoundRace(t *testing.T) {
	// Get succeeds but Delete returns not found (race condition)
	repo := handler.NewMockAPIKeyRepo()
	key := handler.MakeTestAPIKey("del-race-key", "Race Key", types.APIKeySourceAPI, true)
	repo.Seed(key)
	repo.DeleteFn = func(_ context.Context, _ string) error {
		return types.ErrNotFound
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/del-race-key", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// ---------------------------------------------------------------------------
// Tests: ServeKeyHTTP method routing
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_ServeKeyHTTP_MethodNotAllowed(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	methods := []string{http.MethodPost, http.MethodPatch}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), method, "/api/v1/api-keys/some-key", nil, handler.ApikeyAdminKey())
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Create with no context API key (audit logger branch)
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Create_NoContextAPIKey(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "no-ctx-key",
		Name:      "No Context Key",
		PublicKey: "abcdef",
		Role:      "admin",
	}

	// Request without API key in context
	b, marshalErr := json.Marshal(reqBody)
	require.NoError(t, marshalErr)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	// No API key in context

	rr := httptest.NewRecorder()
	apiKeyMux(t, h).ServeHTTP(rr, req)

	// Should still succeed (audit logger is nil, no context key needed for creation logic)
	assert.Equal(t, http.StatusCreated, rr.Code)
}

// ---------------------------------------------------------------------------
// Tests: Security Validations (rate limit, public key length, last admin, arrays)
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Create_RateLimitBounds(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		rateLimit int
		wantCode  int
	}{
		{"negative", "rl-neg", -1, http.StatusBadRequest},
		{"zero_defaults_to_100", "rl-zero", 0, http.StatusCreated},
		{"valid_min", "rl-min", 1, http.StatusCreated},
		{"valid_max", "rl-max", 10000, http.StatusCreated},
		{"exceeds_max", "rl-over", 10001, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := handler.NewMockAPIKeyRepo()
			h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
			require.NoError(t, err)

			reqBody := handler.CreateAPIKeyRequest{
				ID:        tc.id,
				Name:      "Rate Limit Test",
				PublicKey: "abcdef",
				Role:      "admin",
				RateLimit: tc.rateLimit,
			}

			rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
			assert.Equal(t, tc.wantCode, rr.Code)
		})
	}
}

func TestAPIKeyHandler_Create_PublicKeyTooLong(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	reqBody := handler.CreateAPIKeyRequest{
		ID:        "pk-long",
		Name:      "Long PK",
		PublicKey: strings.Repeat("a", 129),
	}

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPost, "/api/v1/api-keys", reqBody, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "public_key exceeds maximum length")
}

func TestAPIKeyHandler_Update_RateLimitBounds(t *testing.T) {
	tests := []struct {
		name      string
		rateLimit int
		wantCode  int
	}{
		{"negative", -1, http.StatusBadRequest},
		{"zero", 0, http.StatusBadRequest},
		{"valid", 50, http.StatusOK},
		{"exceeds_max", 10001, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := handler.NewMockAPIKeyRepo()
			key := handler.MakeTestAPIKey("rl-upd-key", "RL Key", types.APIKeySourceAPI, true)
			repo.Seed(key)

			h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
			require.NoError(t, err)

			rl := tc.rateLimit
			reqBody := handler.UpdateAPIKeyRequest{RateLimit: &rl}

			rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodPut, "/api/v1/api-keys/rl-upd-key", reqBody, handler.ApikeyAdminKey())
			assert.Equal(t, tc.wantCode, rr.Code)
		})
	}
}

func TestAPIKeyHandler_Delete_LastAdminKey(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	// Only one admin key
	adminKey := handler.MakeTestAPIKey("only-admin", "Only Admin", types.APIKeySourceAPI, true)
	adminKey.Role = types.RoleAdmin
	repo.Seed(adminKey)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/only-admin", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "cannot delete the last admin API key")
}

func TestAPIKeyHandler_Delete_AdminKeyWithOtherAdmins(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	// Two admin keys
	admin1 := handler.MakeTestAPIKey("admin-1", "Admin 1", types.APIKeySourceAPI, true)
	admin1.Role = types.RoleAdmin
	admin2 := handler.MakeTestAPIKey("admin-2", "Admin 2", types.APIKeySourceAPI, true)
	admin2.Role = types.RoleAdmin
	repo.Seed(admin1)
	repo.Seed(admin2)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/admin-1", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify admin-1 is deleted, admin-2 still exists
	_, err = repo.Get(context.Background(), "admin-1")
	assert.ErrorIs(t, err, types.ErrNotFound)
	_, err = repo.Get(context.Background(), "admin-2")
	assert.NoError(t, err)
}

func TestAPIKeyHandler_Delete_NonAdminKeySkipsAdminCheck(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	// Non-admin key — should skip the admin count check entirely
	key := handler.MakeTestAPIKey("non-admin", "Non Admin", types.APIKeySourceAPI, true)
	key.Role = types.RoleStrategy
	repo.Seed(key)

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/non-admin", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAPIKeyHandler_Delete_AdminCountError(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	adminKey := handler.MakeTestAPIKey("admin-err", "Admin Err", types.APIKeySourceAPI, true)
	adminKey.Role = types.RoleAdmin
	repo.Seed(adminKey)
	repo.CountFn = func(_ context.Context, _ storage.APIKeyFilter) (int, error) {
		return 0, fmt.Errorf("count error")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/admin-err", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAPIKeyHandler_Delete_AdminListError(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	adminKey := handler.MakeTestAPIKey("admin-lerr", "Admin ListErr", types.APIKeySourceAPI, true)
	adminKey.Role = types.RoleAdmin
	repo.Seed(adminKey)
	repo.ListFn = func(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
		return nil, fmt.Errorf("list error")
	}

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, apiKeyMux(t, h), http.MethodDelete, "/api/v1/api-keys/admin-lerr", nil, handler.ApikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// ---------------------------------------------------------------------------
// Tests: ListAPIKeyNames (lightweight, any-authenticated endpoint)
// ---------------------------------------------------------------------------

func doAPIKeyNamesRequest(t *testing.T, h *handler.APIKeyHandler, method string, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/api-keys/names", nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rr := httptest.NewRecorder()
	h.ListAPIKeyNames(rr, req)
	return rr
}

func TestAPIKeyHandler_ListNames_NonAdminAllowed(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.Seed(handler.MakeTestAPIKey("admin", "Admin", types.APIKeySourceAPI, true))
	repo.Seed(handler.MakeTestAPIKey("agent", "Agent", types.APIKeySourceConfig, true))

	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	// An agent-role caller (which is forbidden from /api/v1/api-keys at
	// the router layer) must succeed here — that's the whole point of
	// the names projection.
	agentKey := &types.APIKey{ID: "agent", Name: "Agent", Role: types.RoleAgent, Enabled: true}
	rr := doAPIKeyNamesRequest(t, h, http.MethodGet, agentKey)
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var resp handler.ListAPIKeyNamesResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Len(t, resp.Keys, 2)
}

func TestAPIKeyHandler_ListNames_ProjectionStripsAuditFields(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.Seed(handler.MakeTestAPIKey("k1", "Name1", types.APIKeySourceAPI, true))
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyNamesRequest(t, h, http.MethodGet, handler.ApikeyAdminKey())
	require.Equal(t, http.StatusOK, rr.Code)

	// Decode into a loose map so we can pin the surface area —
	// presence of timestamps / rate_limit / source would be a regression.
	var raw map[string][]map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&raw))
	require.Len(t, raw["keys"], 1)
	k := raw["keys"][0]
	assert.ElementsMatch(t,
		[]string{"id", "name", "role", "enabled"},
		mapKeys(k),
		"names projection must contain only id/name/role/enabled",
	)
}

func TestAPIKeyHandler_ListNames_OnlyEnabledKeys(t *testing.T) {
	repo := handler.NewMockAPIKeyRepo()
	repo.Seed(handler.MakeTestAPIKey("k1", "Enabled", types.APIKeySourceAPI, true))
	repo.Seed(handler.MakeTestAPIKey("k2", "Disabled", types.APIKeySourceAPI, false))
	h, err := handler.NewAPIKeyHandler(repo, handler.ApikeyLogger(), nil)
	require.NoError(t, err)

	rr := doAPIKeyNamesRequest(t, h, http.MethodGet, handler.ApikeyAdminKey())
	require.Equal(t, http.StatusOK, rr.Code)

	var resp handler.ListAPIKeyNamesResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, "k1", resp.Keys[0].ID)
}

// TestAPIKeyHandler_ListNames_MethodNotAllowed was removed: its route is method-scoped now (see setupRoutes) and Go's
// ServeMux answers 405 before the handler runs. A test that calls the handler
// directly with the wrong method asserts a check this layer no longer owns —
// and should not own, since the mux cannot forget it.

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
