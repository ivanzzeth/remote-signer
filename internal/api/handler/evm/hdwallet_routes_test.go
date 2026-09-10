// Package evm_test holds the HD-wallet handler's route-level tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S4)
//
// S4 splits HDWalletHandler into one function per method and sub-path and moves
// it onto r.PathValue. The tests below drive those endpoints, and after the
// split an endpoint is reachable only through the route that names it — so
// driving them means going through internal/api's route registration.
//
// ⛔ The tempting way to do that — build an http.ServeMux in the fixture and
// register "/api/v1/evm/hd-wallets" and friends by hand — creates a second
// source of truth for the route table. It drifts from the production
// registration silently: the tests stay green while exercising routes the daemon
// does not serve. So the patterns come from api.hdWalletsModule's Routes(),
// reached through the exported api.Module / api.RouteRegistrar pair.
//
// ⚠️ Which is why this is `package evm_test` and not `package evm`: internal/api
// imports internal/api/handler/evm, so an in-package test file cannot import
// internal/api back — that is an import cycle. An external test package can,
// because nothing imports it. The cost is that these tests can only use exported
// identifiers, and two things follow from it:
//
//   - the HD-wallet DTOs were unexported, so a response could not be decoded
//     into the handler's own type. ✅ S4 exported them (proposal §1.4, §3.3 —
//     they become SDK type names), so the assertions below decode into exactly
//     what the handler encodes and no hand-copied mirror stands between them.
//   - the mocks stayed in package evm (hdwallet_test.go), exported, because
//     signer_response_test.go and signer_readonly_test.go build their fixtures
//     from the same ones. Identifiers from a package's own _test.go files are
//     visible to its external test package, which is what makes that work.
//
// ⚠️ Two HD-wallet tests did NOT move: TestHDWalletHandler_ReadOnly_CreateBlocked
// and _DeriveBlocked in signer_readonly_test.go. They assert the read-only
// guard, not which path reaches it, and they are built from the signer family's
// in-package fixtures. They call the endpoint function directly now, since
// ServeHTTP is gone.
//
// ⚠️ What these tests still do NOT exercise: the middleware chain. The routes
// register as AuthenticatedOnly, whose chain begins with AuthMiddleware, which
// refuses any request lacking X-API-Key-ID / X-Timestamp / X-Signature
// (middleware/auth.go:62-69). Every test below injects its API key through the
// request context instead, as they always have. So the test registrar drops the
// RouteAuth it is handed and registers the bare handler: what moved is dispatch,
// and nothing here asserts anything about authorization.
// ⛔ Do not read a green run as evidence that an HD-wallet route is correctly
// permissioned — it is not, and module_hdwallets.go says so in writing.
package evm_test

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

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------- the registrar ----------

// muxRegistrar satisfies api.RouteRegistrar by putting each pattern into a bare
// mux. ⚠️ It drops the api.RouteAuth on purpose; see the package comment. The
// patterns themselves are not this type's to choose — they arrive from
// hdWalletsModule.Routes(), which is the same call setupRoutes makes.
type muxRegistrar struct{ mux *http.ServeMux }

func (m muxRegistrar) Handle(pattern string, _ api.RouteAuth, h http.Handler) {
	m.mux.Handle(pattern, h)
}

// recordingRegistrar captures what a module registers without a mux.
type recordingRegistrar struct {
	record func(pattern string, auth api.RouteAuth)
}

func (r recordingRegistrar) Handle(pattern string, auth api.RouteAuth, _ http.Handler) {
	r.record(pattern, auth)
}

// hdWalletMux registers the production HD-wallet routes over an otherwise empty
// mux.
//
// ⭐ An empty mux is deliberate: a path no HD-wallet pattern claims must reach
// nothing at all, which is exactly the property direct h.ServeHTTP dispatch
// could not have. TestHDWalletRoutes_UnclaimedPathNoLongerReachesTheHandler
// pins it.
func hdWalletMux(t *testing.T, sm evmchain.SignerManager) http.Handler {
	t.Helper()

	h, err := evm.NewHDWalletHandler(sm, evm.NewTestAccessService(t), slog.Default(), nil)
	require.NoError(t, err)
	mod, err := api.NewHDWalletsModule(h)
	require.NoError(t, err)
	require.NotNil(t, mod, "no module means no pattern would be registered, and every request below "+
		"would 404 for a reason that has nothing to do with what is under test")

	mux := http.NewServeMux()
	mod.Routes(muxRegistrar{mux: mux})
	return mux
}

// TestHDWalletRoutes_RegistersExactlyTheProductionPatterns is the one assertion
// that would notice the harness quietly registering nothing, or registering
// something else. ⚠️ It does not say these patterns are *right* — it says the
// mux the tests below drive is the mux hdWalletsModule builds, which is the only
// reason a green run here means anything about the daemon.
//
// ⛔ Its more important half is the authorization column, and on this module it
// is load-bearing in a way it is not anywhere else: all four routes are
// AuthenticatedOnly with a written reason recording a KNOWN RBAC GAP —
// PermReadHDWallets and PermCreateHDWallet exist, are granted by role, and are
// referenced by no route. Splitting one prefix into four endpoints is exactly
// the moment someone "fixes" that in passing. It is not this PR's to fix (see
// hdWalletGap in module_hdwallets.go): the failure direction is asymmetric — too
// strict shows up in e2e, too loose ships silently — so it goes in its own PR,
// argued on its own. Nothing else in the HD-wallet family would notice a change
// here: the test registrar drops the RouteAuth entirely, so not one test below
// runs the middleware chain. The full reason string is compared, not just the
// shape, so weakening the reason fails here too.
func TestHDWalletRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	h, err := evm.NewHDWalletHandler(newDefaultMockSignerManager(), evm.NewTestAccessService(t), slog.Default(), nil)
	require.NoError(t, err)
	mod, err := api.NewHDWalletsModule(h)
	require.NoError(t, err)
	require.NotNil(t, mod)

	const gap = `authenticated-only("⛔ KNOWN GAP, not a decision: PermReadHDWallets/PermCreateHDWallet exist and are granted by role, ` +
		`but no HD-wallet route references them, so any authenticated key reaches this surface. ` +
		`Left as-is here because assigning the permission is a security decision that has to be made per route, ` +
		`and a too-loose guess would ship silently while a too-strict one would fail e2e.")`

	var got []string
	mod.Routes(recordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got = append(got, pattern+" → "+auth.String())
	}})

	// ⚠️ Order is the registration order, not sorted: a module registering the
	// same set in a different order is a different edit and worth seeing.
	assert.Equal(t, []string{
		"GET /api/v1/evm/hd-wallets → " + gap,
		"POST /api/v1/evm/hd-wallets → " + gap,
		"POST /api/v1/evm/hd-wallets/{address}/derive → " + gap,
		"GET /api/v1/evm/hd-wallets/{address}/derived → " + gap,
	}, got)
	assert.Equal(t, "hd-wallets", mod.Name())
}

// TestHDWalletRoutes_UnclaimedPathNoLongerReachesTheHandler is the evidence that
// the move actually changed something, run as a controlled pair: the same
// request dispatched directly at the endpoint function and dispatched through
// the mux.
//
// ⭐ The list endpoint never looks at the path at all, so called directly it
// answers 200 with a wallet listing for *any* path whatsoever, including one no
// HD-wallet route claims. That is what every test in this file was doing before
// the move: asserting a status code the URL had no influence over. Through the
// mux the same request reaches nothing and gets the mux's own 404.
//
// ⚠️ The `direct` arm is the control, not the harness. Delete it and this test
// degrades to "a 404 came back", which a mux with no routes at all would also
// satisfy.
func TestHDWalletRoutes_UnclaimedPathNoLongerReachesTheHandler(t *testing.T) {
	const unclaimed = "/api/v1/evm/hd-wallets-archive"

	sm := newDefaultMockSignerManager()
	h, err := evm.NewHDWalletHandler(sm, evm.NewTestAccessService(t), slog.Default(), nil)
	require.NoError(t, err)
	mux := hdWalletMux(t, sm)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, unclaimed, nil)
		return req.WithContext(context.WithValue(context.Background(),
			middleware.APIKeyContextKey, adminAPIKey()))
	}

	direct := httptest.NewRecorder()
	h.ListWallets(direct, newReq())
	require.Equal(t, http.StatusOK, direct.Code,
		"premise of this test: called directly, the handler serves %s as though it were /api/v1/evm/hd-wallets. "+
			"If that stops being true the control arm is gone and the routed arm proves nothing on its own", unclaimed)
	require.Contains(t, direct.Body.String(), `"wallets"`)

	routed := httptest.NewRecorder()
	mux.ServeHTTP(routed, newReq())
	assert.Equal(t, http.StatusNotFound, routed.Code,
		"%s is claimed by no HD-wallet pattern, so it must reach no HD-wallet handler", unclaimed)
	assert.NotContains(t, routed.Body.String(), `"wallets"`,
		"the mux answered, but with the handler's listing — a pattern is claiming more than it should")
}

// ---------- fixtures ----------

func newDefaultMockSignerManager() *evm.MockSignerManager {
	return &evm.MockSignerManager{
		HDWalletMgr: &evm.MockHDWalletManager{},
	}
}

// adminAPIKey returns a test admin API key for injection into request context.
func adminAPIKey() *types.APIKey {
	return &types.APIKey{
		ID:   "test-admin",
		Name: "Test Admin",
		Role: types.RoleAdmin,
	}
}

func doRequest(handler http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	return doRequestWithAPIKey(handler, method, path, body, adminAPIKey())
}

func doRequestWithAPIKey(handler http.Handler, method, path string, body interface{}, apiKey *types.APIKey) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		ctx := context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey)
		req = req.WithContext(ctx)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	err := json.NewDecoder(rec.Body).Decode(v)
	require.NoError(t, err, "failed to decode response body: %s", rec.Body.String())
}

// --- Constructor tests ---

func TestNewHDWalletHandler_NilSignerManager(t *testing.T) {
	accessSvc := evm.NewTestAccessService(t)
	_, err := evm.NewHDWalletHandler(nil, accessSvc, slog.Default(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer manager is required")
}

func TestNewHDWalletHandler_NilLogger(t *testing.T) {
	sm := newDefaultMockSignerManager()
	accessSvc := evm.NewTestAccessService(t)
	_, err := evm.NewHDWalletHandler(sm, accessSvc, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

// --- CreateWallet tests ---

func TestHDWalletHandler_CreateWallet(t *testing.T) {
	sm := newDefaultMockSignerManager()
	mux := hdWalletMux(t, sm)

	body := map[string]interface{}{
		"action":   "create",
		"password": "test-password-123",
	}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp evm.HDWalletResponse
	decodeJSON(t, rec, &resp)
	assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", resp.PrimaryAddress)
	assert.Equal(t, "m/44'/60'/0'/0", resp.BasePath)
	assert.Equal(t, 1, resp.DerivedCount)
	require.Len(t, resp.Derived, 1)
	assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", resp.Derived[0].Address)
	assert.Equal(t, "hd_wallet", resp.Derived[0].Type)
	assert.True(t, resp.Derived[0].Enabled)
}

func TestHDWalletHandler_CreateWallet_DefaultAction(t *testing.T) {
	sm := newDefaultMockSignerManager()
	mux := hdWalletMux(t, sm)

	// Empty action defaults to "create"
	body := map[string]interface{}{
		"password": "test-password-123",
	}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp evm.HDWalletResponse
	decodeJSON(t, rec, &resp)
	assert.NotEmpty(t, resp.PrimaryAddress)
}

func TestHDWalletHandler_CreateWallet_WithEntropyBits(t *testing.T) {
	var capturedParams types.CreateHDWalletParams
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.CreateWalletFn = func(_ context.Context, params types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error) {
		// Copy strings defensively: secure.ZeroString will zero the backing array after handler returns.
		params.Password = string([]byte(params.Password))
		capturedParams = params
		return &evmchain.HDWalletInfo{
			PrimaryAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			BasePath:       "m/44'/60'/0'/0",
			DerivedCount:   1,
		}, nil
	}
	mux := hdWalletMux(t, sm)

	body := map[string]interface{}{
		"action":       "create",
		"password":     "test-password-123",
		"entropy_bits": 128,
	}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "test-password-123", capturedParams.Password)
	assert.Equal(t, 128, capturedParams.EntropyBits)
}

func TestHDWalletHandler_CreateWallet_AlreadyExists(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.CreateWalletFn = func(_ context.Context, _ types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error) {
		return nil, fmt.Errorf("wallet already exists")
	}
	mux := hdWalletMux(t, sm)

	body := map[string]interface{}{
		"action":   "create",
		"password": "test-password-123",
	}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusConflict, rec.Code)

	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	assert.Contains(t, errResp["error"], "already exists")
}

func TestHDWalletHandler_CreateWallet_InternalError(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.CreateWalletFn = func(_ context.Context, _ types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error) {
		return nil, fmt.Errorf("something went wrong")
	}
	mux := hdWalletMux(t, sm)

	body := map[string]interface{}{
		"action":   "create",
		"password": "test-password-123",
	}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// --- ImportWallet tests ---

func TestHDWalletHandler_ImportWallet(t *testing.T) {
	var capturedParams types.ImportHDWalletParams
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.ImportWalletFn = func(_ context.Context, params types.ImportHDWalletParams) (*evmchain.HDWalletInfo, error) {
		// Copy strings defensively: secure.ZeroString will zero the backing array after handler returns.
		params.Password = string([]byte(params.Password))
		params.Mnemonic = string([]byte(params.Mnemonic))
		capturedParams = params
		return &evmchain.HDWalletInfo{
			PrimaryAddress: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			BasePath:       "m/44'/60'/0'/0",
			DerivedCount:   1,
			Derived: []types.SignerInfo{
				{Address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", Type: "hd_wallet", Enabled: true},
			},
		}, nil
	}
	mux := hdWalletMux(t, sm)

	body := map[string]interface{}{
		"action":   "import",
		"password": "import-pw",
		"mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp evm.HDWalletResponse
	decodeJSON(t, rec, &resp)
	assert.Equal(t, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", resp.PrimaryAddress)
	assert.Equal(t, "m/44'/60'/0'/0", resp.BasePath)
	assert.Equal(t, 1, resp.DerivedCount)
	require.Len(t, resp.Derived, 1)

	assert.Equal(t, "import-pw", capturedParams.Password)
	assert.Equal(t, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", capturedParams.Mnemonic)
}

func TestHDWalletHandler_ImportWallet_AlreadyExists(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.ImportWalletFn = func(_ context.Context, _ types.ImportHDWalletParams) (*evmchain.HDWalletInfo, error) {
		return nil, fmt.Errorf("wallet already exists")
	}
	mux := hdWalletMux(t, sm)

	body := map[string]interface{}{
		"action":   "import",
		"password": "pw",
		"mnemonic": "test mnemonic words here abandon abandon abandon abandon abandon abandon abandon about",
	}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// --- ListWallets tests ---

func TestHDWalletHandler_ListWallets(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.ListHDWalletsFn = func() []evmchain.HDWalletInfo {
		return []evmchain.HDWalletInfo{
			{
				PrimaryAddress: "0x1111111111111111111111111111111111111111",
				BasePath:       "m/44'/60'/0'/0",
				DerivedCount:   3,
			},
			{
				PrimaryAddress: "0x2222222222222222222222222222222222222222",
				BasePath:       "m/44'/60'/0'/0",
				DerivedCount:   1,
			},
		}
	}
	mux := hdWalletMux(t, sm)

	rec := doRequest(mux, http.MethodGet, "/api/v1/evm/hd-wallets", nil)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp evm.ListHDWalletsResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Wallets, 2)
	assert.Equal(t, "0x1111111111111111111111111111111111111111", resp.Wallets[0].PrimaryAddress)
	assert.Equal(t, 3, resp.Wallets[0].DerivedCount)
	assert.Equal(t, "0x2222222222222222222222222222222222222222", resp.Wallets[1].PrimaryAddress)
	assert.Equal(t, 1, resp.Wallets[1].DerivedCount)
}

func TestHDWalletHandler_ListWallets_Empty(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.ListHDWalletsFn = func() []evmchain.HDWalletInfo {
		return []evmchain.HDWalletInfo{}
	}
	mux := hdWalletMux(t, sm)

	rec := doRequest(mux, http.MethodGet, "/api/v1/evm/hd-wallets", nil)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp evm.ListHDWalletsResponse
	decodeJSON(t, rec, &resp)
	assert.Len(t, resp.Wallets, 0)
}

// --- DeriveAddress tests ---

func TestHDWalletHandler_DeriveAddress(t *testing.T) {
	sm := newDefaultMockSignerManager()
	mux := hdWalletMux(t, sm)

	index := uint32(5)
	body := evm.DeriveRequest{Index: &index}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp evm.DeriveResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Derived, 1)
	assert.Equal(t, "hd_wallet", resp.Derived[0].Type)
	assert.True(t, resp.Derived[0].Enabled)
}

func TestHDWalletHandler_DeriveAddress_CapturedParams(t *testing.T) {
	var capturedAddr string
	var capturedIndex uint32
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.DeriveAddressFn = func(_ context.Context, primaryAddr string, index uint32) (*types.SignerInfo, error) {
		capturedAddr = primaryAddr
		capturedIndex = index
		return &types.SignerInfo{
			Address: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			Type:    "hd_wallet",
			Enabled: true,
		}, nil
	}
	mux := hdWalletMux(t, sm)

	index := uint32(42)
	body := evm.DeriveRequest{Index: &index}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "0x1111111111111111111111111111111111111111", capturedAddr)
	assert.Equal(t, uint32(42), capturedIndex)

	var resp evm.DeriveResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Derived, 1)
	assert.Equal(t, "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", resp.Derived[0].Address)
}

func TestHDWalletHandler_DeriveAddress_Error(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.DeriveAddressFn = func(_ context.Context, _ string, _ uint32) (*types.SignerInfo, error) {
		return nil, fmt.Errorf("derivation failed")
	}
	mux := hdWalletMux(t, sm)

	index := uint32(0)
	body := evm.DeriveRequest{Index: &index}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	assert.Contains(t, errResp["error"], "derivation failed")
}

// --- DeriveBatch tests ---

func TestHDWalletHandler_DeriveBatch(t *testing.T) {
	sm := newDefaultMockSignerManager()
	mux := hdWalletMux(t, sm)

	start := uint32(0)
	count := uint32(3)
	body := evm.DeriveRequest{Start: &start, Count: &count}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp evm.DeriveResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Derived, 3)
	for _, d := range resp.Derived {
		assert.Equal(t, "hd_wallet", d.Type)
		assert.True(t, d.Enabled)
	}
}

func TestHDWalletHandler_DeriveBatch_CapturedParams(t *testing.T) {
	var capturedAddr string
	var capturedStart, capturedCount uint32
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.DeriveAddressesFn = func(_ context.Context, primaryAddr string, start, count uint32) ([]types.SignerInfo, error) {
		capturedAddr = primaryAddr
		capturedStart = start
		capturedCount = count
		return []types.SignerInfo{
			{Address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Type: "hd_wallet", Enabled: true},
			{Address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Type: "hd_wallet", Enabled: true},
		}, nil
	}
	mux := hdWalletMux(t, sm)

	start := uint32(10)
	count := uint32(2)
	body := evm.DeriveRequest{Start: &start, Count: &count}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD/derive", body)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD", capturedAddr)
	assert.Equal(t, uint32(10), capturedStart)
	assert.Equal(t, uint32(2), capturedCount)
}

func TestHDWalletHandler_DeriveBatch_Error(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.DeriveAddressesFn = func(_ context.Context, _ string, _, _ uint32) ([]types.SignerInfo, error) {
		return nil, fmt.Errorf("batch derivation failed")
	}
	mux := hdWalletMux(t, sm)

	start := uint32(0)
	count := uint32(5)
	body := evm.DeriveRequest{Start: &start, Count: &count}
	rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// --- ListDerived tests ---

func TestHDWalletHandler_ListDerived(t *testing.T) {
	sm := newDefaultMockSignerManager()
	ix0 := uint32(0)
	ix1 := uint32(1)
	sm.HDWalletMgr.ListDerivedAddrsFn = func(primaryAddr string) ([]types.SignerInfo, error) {
		assert.Equal(t, "0x1111111111111111111111111111111111111111", primaryAddr)
		return []types.SignerInfo{
			{
				Address:           "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				Type:              "hd_wallet",
				Enabled:           true,
				HDParentAddress:   primaryAddr,
				HDDerivationIndex: &ix0,
			},
			{
				Address:           "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
				Type:              "hd_wallet",
				Enabled:           false,
				HDParentAddress:   primaryAddr,
				HDDerivationIndex: &ix1,
			},
		}, nil
	}
	mux := hdWalletMux(t, sm)

	rec := doRequest(mux, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derived", nil)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp evm.ListDerivedResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Derived, 2)
	assert.Equal(t, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", resp.Derived[0].Address)
	assert.True(t, resp.Derived[0].Enabled)
	require.NotNil(t, resp.Derived[0].HDDerivationIndex)
	assert.Equal(t, uint32(0), *resp.Derived[0].HDDerivationIndex)
	assert.Equal(t, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", resp.Derived[1].Address)
	assert.False(t, resp.Derived[1].Enabled)
	require.NotNil(t, resp.Derived[1].HDDerivationIndex)
	assert.Equal(t, uint32(1), *resp.Derived[1].HDDerivationIndex)
}

func TestHDWalletHandler_ListDerived_Error(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.HDWalletMgr.ListDerivedAddrsFn = func(_ string) ([]types.SignerInfo, error) {
		return nil, fmt.Errorf("wallet not found")
	}
	mux := hdWalletMux(t, sm)

	rec := doRequest(mux, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derived", nil)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	assert.Contains(t, errResp["error"], "wallet not found")
}

// --- Validation error tests ---

func TestHDWalletHandler_ValidationErrors(t *testing.T) {
	t.Run("missing password on create", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		body := map[string]interface{}{
			"action": "create",
		}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "password is required")
	})

	t.Run("missing password on import", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		body := map[string]interface{}{
			"action":   "import",
			"mnemonic": "test mnemonic",
		}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "password is required")
	})

	t.Run("missing mnemonic on import", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		body := map[string]interface{}{
			"action":   "import",
			"password": "test-password",
		}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "mnemonic or wallet_json is required for import")
	})

	t.Run("invalid action", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		body := map[string]interface{}{
			"action":   "delete",
			"password": "test-password",
		}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "action must be 'create' or 'import'")
	})

	t.Run("invalid JSON body", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/hd-wallets", bytes.NewBufferString("{invalid json"))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "invalid request body")
	})

	t.Run("invalid address in path", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/not-an-address/derive", map[string]interface{}{"index": 0})

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "invalid path or address")
	})

	t.Run("address too short", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1234/derive", map[string]interface{}{"index": 0})

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ⚠️ Renamed, and the rename is the record of a deliberate change. It used
	// to be "unknown action path" and it asserted the handler's own
	// 404 {"error":"unknown action"} — an answer that only existed because the
	// "/api/v1/evm/hd-wallets/" prefix pattern let a path with any third segment
	// reach the handler at all. No pattern claims that path now. The status code
	// is unchanged (404 either way); what changed is who produced it, and in a
	// daemon the body is the /api/v1/ fallback's JSON rather than this mux's
	// plain text. Recorded in the table on hdWalletsModule.Routes.
	t.Run("unknown action path reaches no route", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		rec := doRequest(mux, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/unknown", nil)

		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.NotContains(t, rec.Body.String(), "unknown action",
			"the handler answered — some pattern is still claiming a path that is not an HD-wallet endpoint")
	})

	t.Run("derive missing index and start+count", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		body := map[string]interface{}{}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "either 'index' or 'start'+'count' is required")
	})

	t.Run("derive count zero", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		start := uint32(0)
		count := uint32(0)
		body := evm.DeriveRequest{Start: &start, Count: &count}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "count must be between 1 and 100")
	})

	t.Run("derive count exceeds 100", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		start := uint32(0)
		count := uint32(101)
		body := evm.DeriveRequest{Start: &start, Count: &count}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "count must be between 1 and 100")
	})

	t.Run("derive with invalid JSON body", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		mux := hdWalletMux(t, sm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", bytes.NewBufferString("{bad"))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// --- Method not allowed tests ---

// TestHDWalletHandler_MethodNotAllowed was removed: its route is method-scoped now (see setupRoutes) and Go's
// ServeMux answers 405 before the handler runs. A test that calls the handler
// directly with the wrong method asserts a check this layer no longer owns —
// and should not own, since the mux cannot forget it.

// --- HDWalletManager not configured tests ---

func TestHDWalletHandler_HDWalletNotConfigured(t *testing.T) {
	t.Run("create when not configured", func(t *testing.T) {
		sm := &evm.MockSignerManager{
			HDWalletMgrErr: types.ErrHDWalletNotConfigured,
		}
		mux := hdWalletMux(t, sm)

		body := map[string]interface{}{
			"action":   "create",
			"password": "test",
		}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusNotImplemented, rec.Code)
	})

	t.Run("list when not configured", func(t *testing.T) {
		sm := &evm.MockSignerManager{
			HDWalletMgrErr: types.ErrHDWalletNotConfigured,
		}
		mux := hdWalletMux(t, sm)

		rec := doRequest(mux, http.MethodGet, "/api/v1/evm/hd-wallets", nil)

		assert.Equal(t, http.StatusNotImplemented, rec.Code)
	})

	t.Run("derive when not configured", func(t *testing.T) {
		sm := &evm.MockSignerManager{
			HDWalletMgrErr: types.ErrHDWalletNotConfigured,
		}
		mux := hdWalletMux(t, sm)

		index := uint32(0)
		body := evm.DeriveRequest{Index: &index}
		rec := doRequest(mux, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

		assert.Equal(t, http.StatusNotImplemented, rec.Code)
	})

	t.Run("list derived when not configured", func(t *testing.T) {
		sm := &evm.MockSignerManager{
			HDWalletMgrErr: types.ErrHDWalletNotConfigured,
		}
		mux := hdWalletMux(t, sm)

		rec := doRequest(mux, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derived", nil)

		assert.Equal(t, http.StatusNotImplemented, rec.Code)
	})
}

// --- Trailing slash ---

// TestHDWalletRoutes_TrailingSlashNoLongerForgiven replaces
// TestHDWalletHandler_TrailingSlash, which asserted that
// GET /api/v1/evm/hd-wallets/ returned the wallet list. It did, because
// ServeHTTP ran TrimSuffix(path, "/") and the "/api/v1/evm/hd-wallets/" prefix
// pattern delivered the request to it.
//
// ⛔ This is a client-visible break and it is the reason this test was rewritten
// rather than deleted: deleting it would have removed the only place the repo
// says out loud what these four URLs do. Go's ServeMux never strips a trailing
// slash — it only ever *adds* one, to redirect into a subtree pattern — so with
// the prefix gone all four are unmatched. The repo's own SDKs never send that
// shape, but a hand-written client that did would now get a 404.
//
// ⚠️ In a daemon the answer is the /api/v1/ fallback's JSON 404, not this bare
// mux's plain-text one; the status is the same either way.
func TestHDWalletRoutes_TrailingSlashNoLongerForgiven(t *testing.T) {
	sm := newDefaultMockSignerManager()
	mux := hdWalletMux(t, sm)

	const addr = "0x1111111111111111111111111111111111111111"
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/evm/hd-wallets/"},
		{http.MethodPost, "/api/v1/evm/hd-wallets/"},
		{http.MethodPost, "/api/v1/evm/hd-wallets/" + addr + "/derive/"},
		{http.MethodGet, "/api/v1/evm/hd-wallets/" + addr + "/derived/"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := doRequest(mux, tc.method, tc.path, map[string]interface{}{"password": "pw"})
			assert.Equal(t, http.StatusNotFound, rec.Code,
				"a trailing slash is a different path and no pattern claims it")
		})
	}
}
