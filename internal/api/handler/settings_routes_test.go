// Package handler_test — this file holds the settings handler's route-level
// tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S5)
//
// S5 splits SettingsHandler into one function per group per method and deletes
// ServeHTTP. The tests below drive those endpoints, and after the split an
// endpoint is reachable only through the route that names it — so driving them
// means going through internal/api's route registration.
//
// ⛔ The tempting way to do that — build an http.ServeMux in the fixture and
// register "/api/v1/admin/settings/security" and friends by hand — creates a
// second source of truth for the route table, eighteen lines of it. It drifts
// from the production registration silently: the tests stay green while
// exercising routes the daemon does not serve. So the patterns come from
// api.settingsModule's Routes(), reached through the exported api.Module /
// api.RouteRegistrar pair.
//
// ⚠️ Which is why this is `package handler_test`: internal/api imports
// internal/api/handler, so an in-package test file cannot import internal/api
// back — that is an import cycle. The cost is that these tests can only use
// exported identifiers; the settings snapshot types already were, and the shared
// fake store, logger and fixture constructor are exported from settings_test.go
// for this (see the note there).
//
// ⚠️ Three settings tests did NOT move. TestWriteSettingsJSON and the two
// recordAudit tests call unexported identifiers and so cannot leave package
// handler; TestCoverage_Settings_Put_Error in coverage_boost_test.go wraps the
// unexported errorSettingsStore and stays too, calling the endpoint functions
// directly.
//
// ⚠️ What these tests still do NOT exercise: the middleware chain. All eighteen
// routes register as Permitted(PermManageSettings), whose chain begins with
// AuthMiddleware, which refuses any request lacking X-API-Key-ID / X-Timestamp /
// X-Signature. Every test below injects its API key through the request context
// instead, as they always have. So the test registrar drops the RouteAuth it is
// handed and registers the bare handler: what moved is dispatch, and nothing
// here asserts anything about authorization. ⛔ Do not read a green run as
// evidence that a settings route is correctly permissioned — that lives in the
// archcheck route-auth gates and their baselines, and in the pattern assertion
// below.
package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// ---------- the registrar ----------
//
// ⚠️ Named settings* rather than reusing the wallet or api-key families'
// registrars: wallet_routes_test.go is behind `//go:build integration` in this
// same external package, so under that tag the files compile together and a
// shared name would be a redeclaration. Same shape, different name.

type settingsMuxRegistrar struct{ mux *http.ServeMux }

func (m settingsMuxRegistrar) Handle(pattern string, _ api.RouteAuth, h http.Handler) {
	m.mux.Handle(pattern, h)
}

type settingsRecordingRegistrar struct {
	record func(pattern string, auth api.RouteAuth)
}

func (r settingsRecordingRegistrar) Handle(pattern string, auth api.RouteAuth, _ http.Handler) {
	r.record(pattern, auth)
}

// settingsMux registers the production settings routes over an otherwise empty
// mux.
//
// ⭐ An empty mux is deliberate: a path no settings pattern claims must reach
// nothing at all, which is exactly the property direct h.ServeHTTP dispatch
// could not have. TestSettingsRoutes_UnclaimedPathNoLongerReachesTheHandler
// pins it.
func settingsMux(t *testing.T, h *handler.SettingsHandler) http.Handler {
	t.Helper()
	mod, err := api.NewSettingsModule(h)
	require.NoError(t, err)
	require.NotNil(t, mod, "no module means no pattern would be registered, and every request below "+
		"would 404 for a reason that has nothing to do with what is under test")

	mux := http.NewServeMux()
	mod.Routes(settingsMuxRegistrar{mux: mux})
	return mux
}

func settingsAdminKey() *types.APIKey {
	return &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
}

// doSettingsRequest replaces this file's old direct h.ServeHTTP calls. ⭐ That it
// takes no hint about which endpoint it means IS the change: the mux decides
// from the method and the path, exactly as it does in the daemon.
func doSettingsRequest(t *testing.T, mux http.Handler, method, path, body string, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestSettingsRoutes_RegistersExactlyTheProductionPatterns is the one assertion
// that would notice the harness quietly registering nothing, or registering
// something else. ⚠️ It does not say these patterns are *right* — it says the
// mux the tests below drive is the mux settingsModule builds, which is the only
// reason a green run here means anything about the daemon.
//
// ⛔ Its more important half is the authorization column. Splitting one prefix
// into eighteen endpoints is exactly the moment a reviewer's eye slides past
// `Permitted(PermManageSettings)` on the nine GET routes and someone "improves"
// one to a read permission — nine of these eighteen are reads, and a read
// permission on them would look like tidying up. It would also be the change
// nothing else catches: route-mutating-perm only sees a *write* on a read
// permission, and proposal §0 records that loosening a read route is the one
// direction all fifteen gates are blind to. Nothing else in the settings family
// would notice either: the test registrar drops the RouteAuth entirely, so not
// one test below runs the middleware chain.
//
// ⭐ The group list is compared as one literal block rather than derived from
// settings.Group constants. Deriving it would make this test agree with the
// module by construction whatever either of them said — the point is to state
// the eighteen route strings a second time, by hand, so that changing one of
// them takes two edits and a reviewer's eye.
func TestSettingsRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	mod, err := api.NewSettingsModule(h)
	require.NoError(t, err)
	require.NotNil(t, mod)

	var got []string
	mod.Routes(settingsRecordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got = append(got, pattern+" → "+auth.String())
	}})

	// ⚠️ Order is the registration order, not sorted: a module registering the
	// same set in a different order is a different edit and worth seeing.
	assert.Equal(t, []string{
		"GET /api/v1/admin/settings/security → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/security → permitted(manage_settings)",
		"GET /api/v1/admin/settings/notify → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/notify → permitted(manage_settings)",
		"GET /api/v1/admin/settings/audit_monitor → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/audit_monitor → permitted(manage_settings)",
		"GET /api/v1/admin/settings/evm.dynamic_blocklist → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/evm.dynamic_blocklist → permitted(manage_settings)",
		"GET /api/v1/admin/settings/evm.simulation → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/evm.simulation → permitted(manage_settings)",
		"GET /api/v1/admin/settings/evm.foundry → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/evm.foundry → permitted(manage_settings)",
		"GET /api/v1/admin/settings/evm.rpc_gateway → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/evm.rpc_gateway → permitted(manage_settings)",
		"GET /api/v1/admin/settings/evm.material_check → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/evm.material_check → permitted(manage_settings)",
		"GET /api/v1/admin/settings/web → permitted(manage_settings)",
		"PUT /api/v1/admin/settings/web → permitted(manage_settings)",
	}, got)
	assert.Equal(t, "settings", mod.Name())
}

// TestSettingsRoutes_EveryGroupHasBothRoutes is the other half of the pattern
// assertion, and the one that would notice a group being *dropped*. The literal
// block above is a second source of truth on purpose; this one is derived from
// internal/settings' own group table, so a tenth group added there with no
// routes fails here by name.
//
// ⭐ The old handler could not have had this test: the group table and the
// dispatch switch were two lists that had to be kept in step by hand, and
// nothing compared them. The proof that they had drifted apart is in the
// handler's own default arm — "unknown **or read-only** settings group" — which
// described a category (a group with a GET and no PUT) that had not existed for
// some time.
func TestSettingsRoutes_EveryGroupHasBothRoutes(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	mod, err := api.NewSettingsModule(h)
	require.NoError(t, err)

	registered := map[string]bool{}
	mod.Routes(settingsRecordingRegistrar{record: func(pattern string, _ api.RouteAuth) {
		registered[pattern] = true
	}})

	groups := []settings.Group{
		settings.GroupSecurity,
		settings.GroupNotify,
		settings.GroupAuditMonitor,
		settings.GroupBlocklist,
		settings.GroupSimulation,
		settings.GroupFoundry,
		settings.GroupRPCGateway,
		settings.GroupMaterialCheck,
		settings.GroupWeb,
	}
	for _, g := range groups {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			pattern := method + " /api/v1/admin/settings/" + string(g)
			assert.True(t, registered[pattern],
				"group %q has no %s route — either the group table in internal/settings/model.go grew "+
					"and settingsModule did not, or a route was renamed", g, method)
		}
	}
	assert.Len(t, registered, 2*len(groups),
		"the module registers routes that are not <method> /api/v1/admin/settings/<a known group>")
}

// TestSettingsRoutes_UnclaimedPathNoLongerReachesTheHandler is the evidence that
// the move actually changed something, run as a controlled pair: the same
// request dispatched at the endpoint function and dispatched through the mux.
//
// ⭐ GetSecurity never looks at the path at all, so called directly it answers
// 200 with the security snapshot for *any* path whatsoever. That is what every
// test in this family was doing before the move: asserting a status code the URL
// had partial influence over. Through the mux the same request reaches nothing.
//
// ⚠️ The `direct` arm is the control, not the harness. Delete it and this test
// degrades to "a 404 came back", which a mux with no routes at all would also
// satisfy.
func TestSettingsRoutes_UnclaimedPathNoLongerReachesTheHandler(t *testing.T) {
	const unclaimed = "/api/v1/admin/settings-archive"

	h, _ := handler.NewSettingsHandlerForTest(t)
	mux := settingsMux(t, h)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, unclaimed, nil)
		return req.WithContext(context.WithValue(context.Background(),
			middleware.APIKeyContextKey, settingsAdminKey()))
	}

	direct := httptest.NewRecorder()
	h.GetSecurity(direct, newReq())
	require.Equal(t, http.StatusOK, direct.Code,
		"premise of this test: called directly, the endpoint serves %s as though it were the security "+
			"group. If that stops being true the control arm is gone and the routed arm proves nothing", unclaimed)
	require.Contains(t, direct.Body.String(), `"nonce_required"`)

	routed := httptest.NewRecorder()
	mux.ServeHTTP(routed, newReq())
	assert.Equal(t, http.StatusNotFound, routed.Code,
		"%s is claimed by no settings pattern, so it must reach no settings handler", unclaimed)
	assert.NotContains(t, routed.Body.String(), `"nonce_required"`,
		"the mux answered, but with a snapshot — a pattern is claiming more than it should")
}

func TestNewSettingsHandler(t *testing.T) {
	mgr := settings.NewManager(handler.NewFakeSettingsStore(), handler.SettingsTestLogger())
	h := handler.NewSettingsHandler(mgr, handler.SettingsTestLogger())
	assert.NotNil(t, h)
}

func TestSettingsHandler_SetAuditLogger(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	h.SetAuditLogger(nil) // just ensure no panic
}

// ---------------------------------------------------------------------------
// Paths that used to reach the handler and no longer do
// ---------------------------------------------------------------------------
//
// ⚠️ Each of the three below replaces a test that asserted the handler's own 400
// on a malformed path. They are rewritten rather than deleted because they are
// the only place the repo says out loud what these URLs do — and the answer
// changed, so the name says so. See settingsModule.Routes for the measured
// before/after table; ⛔ in a daemon these are the /api/v1/ JSON 404, not this
// bare mux's plain-text one.

// TestSettingsRoutes_NoGroup_NoLongerReachesTheHandler replaces
// TestSettingsHandler_ServeHTTP_NoGroup.
//
// ⛔ Client-visible: GET /api/v1/admin/settings/ used to answer 400
// "group required: /api/v1/admin/settings/<group>" — a guard that only existed
// because a prefix pattern let a request with no group reach the handler at all.
func TestSettingsRoutes_NoGroup_NoLongerReachesTheHandler(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	rr := doSettingsRequest(t, settingsMux(t, h), http.MethodGet, "/api/v1/admin/settings/", "", settingsAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.NotContains(t, rr.Body.String(), "group required",
		"the handler answered — some pattern is still claiming a path with no group in it")
}

// TestSettingsRoutes_DeepPath_NoLongerReachesTheHandler replaces
// TestSettingsHandler_ServeHTTP_GroupWithSlash.
//
// ⚠️ Unlike the signers' `.../access/a/b`, which returned a real access list, a
// deep settings path was already refused: the handler's
// strings.Contains(group, "/") guard answered 400. So no data was ever exposed
// here; what changes is only which layer says no.
func TestSettingsRoutes_DeepPath_NoLongerReachesTheHandler(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	for _, path := range []string{
		"/api/v1/admin/settings/security/extra",
		"/api/v1/admin/settings/a/b/c/d",
		// ⚠️ Trailing slash, and in the direction opposite to hd-wallets: the old
		// handler did NOT run TrimSuffix, so "security/" was rejected by the same
		// slash guard rather than forgiven. It was never served.
		"/api/v1/admin/settings/security/",
		"/api/v1/admin/settings/evm.foundry/",
	} {
		t.Run(path, func(t *testing.T) {
			rr := doSettingsRequest(t, settingsMux(t, h), http.MethodGet, path, "", settingsAdminKey())
			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.NotContains(t, rr.Body.String(), "group required",
				"the handler answered — a settings pattern is claiming a path deeper than one group")
		})
	}
}

// TestSettingsRoutes_UnknownGroup_NoLongerReachesTheHandler replaces
// TestSettingsHandler_GET_UnknownGroup and TestSettingsHandler_PUT_UnknownGroup.
//
// ⚠️ The GET status is unchanged (404) and the PUT status changes (400 → 404);
// what changed for both is that no handler runs. The two old messages —
// "unknown settings group" and "unknown or read-only settings group" — are gone
// with the switch that produced them, so the assertion is on their absence.
func TestSettingsRoutes_UnknownGroup_NoLongerReachesTheHandler(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			rr := doSettingsRequest(t, settingsMux(t, h), method,
				"/api/v1/admin/settings/unknown.group", `{"enabled":true}`, settingsAdminKey())
			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.NotContains(t, rr.Body.String(), "settings group",
				"the handler answered — a settings pattern is claiming a group that has no route")
		})
	}
}

// TestSettingsRoutes_WrongVerbIsRefusedByTheMux replaces
// TestSettingsHandler_ServeHTTP_MethodNotAllowed, and is deliberately stronger
// than it.
//
// ⚠️ Settings never had the verb hole that signers and hd-wallets did: ServeHTTP
// dispatched on `switch r.Method` with a 405 default, so a GET could not write.
// ⭐ What changes is who enforces it. The old rule lived in a switch someone had
// to remember to write; it now lives in the pattern, which the mux cannot forget
// — GET and PUT are registered on this path and nothing else is.
//
// ⛔ The status alone would be a weak assertion: a handler that mutated and then
// wrote 405 would satisfy it. So the manager is read back afterwards, which is
// the property that actually matters.
func TestSettingsRoutes_WrongVerbIsRefusedByTheMux(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			h, mgr := handler.NewSettingsHandlerForTest(t)
			require.False(t, mgr.Foundry().Enabled, "fixture premise: foundry starts disabled")

			rr := doSettingsRequest(t, settingsMux(t, h), method,
				"/api/v1/admin/settings/evm.foundry", `{"enabled":true}`, settingsAdminKey())

			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
			assert.False(t, mgr.Foundry().Enabled,
				"%s reached a settings endpoint — the state change happened", method)
			// ⚠️ 405 is what this bare mux answers because GET and PUT are
			// registered on the same path. ⛔ A daemon answers 404 instead:
			// "/api/v1/" matches every method, so the request reaches the JSON-404
			// fallback (proposal §0 correction 9). Nothing in this package can see
			// that; the fallback is registered by the router, not by the module.
			assert.NotContains(t, rr.Body.String(), "method not allowed",
				"the handler's own 405 text came back, which means it decided the method again — "+
					"that decision belongs to the route now")
		})
	}
}

// TestSettingsRoutes_HeadIsServedByTheGetRoute pins the one row in this step's
// behaviour table that goes the *widening* way: HEAD used to be 405 (the old
// switch had no HEAD arm and fell to its default) and is now served by the GET
// route, because Go's mux matches HEAD against a GET pattern.
//
// ⭐ New in S5, and it exists because the change was found by measuring rather
// than by reading. A widening is the direction worth a test: all nine GET
// endpoints are pure reads and answering HEAD like GET is what HTTP prescribes,
// but "it only reaches a read" is the part that has to stay true, so the manager
// is read back.
func TestSettingsRoutes_HeadIsServedByTheGetRoute(t *testing.T) {
	h, mgr := handler.NewSettingsHandlerForTest(t)
	require.False(t, mgr.Foundry().Enabled, "fixture premise: foundry starts disabled")

	rr := doSettingsRequest(t, settingsMux(t, h), http.MethodHead,
		"/api/v1/admin/settings/evm.foundry", `{"enabled":true}`, settingsAdminKey())

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.False(t, mgr.Foundry().Enabled, "HEAD reached a write endpoint — the state change happened")
}

// ---------------------------------------------------------------------------
// GET — all nine groups
// ---------------------------------------------------------------------------

func TestSettingsHandler_GET_Security(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	rr := doSettingsRequest(t, settingsMux(t, h), http.MethodGet, "/api/v1/admin/settings/security", "", settingsAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var s settings.SecuritySnapshot
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &s))
	assert.True(t, s.NonceRequired)
}

// TestSettingsHandler_GET_EveryGroup absorbs the eight one-line GET tests that
// asserted nothing but 200: GET_Notify, GET_AuditMonitor, GET_Blocklist,
// GET_Simulation, GET_Foundry, GET_RPCGateway, GET_MaterialCheck and GET_Web.
// ⚠️ They are table rows now rather than eight copies of one function, and the
// row list comes from the module's own GET patterns, so a group added to the
// module is covered here without an edit. Security keeps its own test above
// because it asserts a field, not just a status.
func TestSettingsHandler_GET_EveryGroup(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	mod, err := api.NewSettingsModule(h)
	require.NoError(t, err)

	var paths []string
	mod.Routes(settingsRecordingRegistrar{record: func(pattern string, _ api.RouteAuth) {
		if method, path, ok := cutMethod(pattern); ok && method == http.MethodGet {
			paths = append(paths, path)
		}
	}})
	require.Len(t, paths, 9, "nine groups, nine GET routes — the rows below would otherwise pass for the wrong reason")

	mux := settingsMux(t, h)
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			rr := doSettingsRequest(t, mux, http.MethodGet, path, "", settingsAdminKey())
			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			var any map[string]interface{}
			assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &any))
		})
	}
}

func cutMethod(pattern string) (method, path string, ok bool) {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == ' ' {
			return pattern[:i], pattern[i+1:], true
		}
	}
	return "", pattern, false
}

// ---------------------------------------------------------------------------
// PUT — security group
// ---------------------------------------------------------------------------

func TestSettingsHandler_PUT_Security(t *testing.T) {
	h, mgr := handler.NewSettingsHandlerForTest(t)
	rr := doSettingsRequest(t, settingsMux(t, h), http.MethodPut, "/api/v1/admin/settings/security",
		`{"nonce_required": false, "rate_limit_default": 200}`, settingsAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	assert.False(t, mgr.Security().NonceRequired)
	assert.Equal(t, 200, mgr.Security().RateLimitDefault)
}

// TestSettingsHandler_PUT_Security_OnSecurityUpdatedHook pins the one thing that
// distinguishes PutSecurity from the other eight: the router hands it
// syncApprovalGuard through SetOnSecurityUpdated, and a settings write that did
// not fire it would leave the approval policy stale until the next restart.
//
// ⭐ New in S5. The hook existed before and nothing tested it — which mattered
// more once the nine PUT arms became nine functions over one shared helper,
// because "the hook is only on this one" is now a property of one call site
// rather than of one switch arm a reader can see next to the other eight.
func TestSettingsHandler_PUT_Security_OnSecurityUpdatedHook(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	fired := 0
	h.SetOnSecurityUpdated(func() { fired++ })
	mux := settingsMux(t, h)

	rr := doSettingsRequest(t, mux, http.MethodPut, "/api/v1/admin/settings/security",
		`{"nonce_required": false}`, settingsAdminKey())
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, 1, fired, "PUT security did not fire the on-security-updated hook")

	// ⛔ And it fires for security only: a write to another group must not
	// re-run the approval-guard sync.
	rr = doSettingsRequest(t, mux, http.MethodPut, "/api/v1/admin/settings/evm.foundry",
		`{"enabled": true}`, settingsAdminKey())
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, 1, fired, "a non-security group fired the on-security-updated hook")
}

// ---------------------------------------------------------------------------
// PUT — all nine groups, valid and invalid bodies
// ---------------------------------------------------------------------------

// TestSettingsHandler_PUT_EveryGroup absorbs the eight per-group PUT tests
// (PUT_Notify, PUT_AuditMonitor, PUT_Blocklist, PUT_Simulation, PUT_Foundry,
// PUT_RPCGateway, PUT_MaterialCheck, PUT_Web) into one table. ⭐ Each row is a
// *different body type* at a *different path*, which is the whole subject of
// this step: before S5 all nine went to one path and the type was picked from a
// path segment.
func TestSettingsHandler_PUT_EveryGroup(t *testing.T) {
	for _, tc := range []struct {
		group string
		body  string
	}{
		{"notify", `{"providers": {}, "channels": {}}`},
		{"audit_monitor", `{"enabled": true, "interval": 60000000000}`},
		{"evm.dynamic_blocklist", `{"enabled": true, "sources": []}`},
		{"evm.simulation", `{"enabled": true, "timeout": 30000000000}`},
		{"evm.foundry", `{"enabled": true}`},
		{"evm.rpc_gateway", `{"base_url": "http://localhost:8545"}`},
		{"evm.material_check", `{"enabled": true}`},
		{"web", `{"enabled": false}`},
	} {
		t.Run(tc.group, func(t *testing.T) {
			h, _ := handler.NewSettingsHandlerForTest(t)
			rr := doSettingsRequest(t, settingsMux(t, h), http.MethodPut,
				"/api/v1/admin/settings/"+tc.group, tc.body, settingsAdminKey())
			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		})
	}
}

// TestSettingsHandler_PUT_InvalidJSON absorbs the nine per-group
// *_InvalidJSON tests. The rows come from the module's own PUT patterns, so a
// group added to the module is covered without an edit here.
func TestSettingsHandler_PUT_InvalidJSON(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	mod, err := api.NewSettingsModule(h)
	require.NoError(t, err)

	var paths []string
	mod.Routes(settingsRecordingRegistrar{record: func(pattern string, _ api.RouteAuth) {
		if method, path, ok := cutMethod(pattern); ok && method == http.MethodPut {
			paths = append(paths, path)
		}
	}})
	require.Len(t, paths, 9, "nine groups, nine PUT routes — the rows below would otherwise pass for the wrong reason")

	mux := settingsMux(t, h)
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			rr := doSettingsRequest(t, mux, http.MethodPut, path, `{invalid json`, settingsAdminKey())
			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Contains(t, rr.Body.String(), "invalid JSON")
		})
	}
}

// ---------------------------------------------------------------------------
// PUT with API key in context (actor = key ID)
// ---------------------------------------------------------------------------

func TestSettingsHandler_PUT_WithAPIKeyActor(t *testing.T) {
	h, _ := handler.NewSettingsHandlerForTest(t)
	rr := doSettingsRequest(t, settingsMux(t, h), http.MethodPut, "/api/v1/admin/settings/security",
		`{"max_request_age": 120000000000}`, // 2 minutes
		&types.APIKey{ID: "my-key", Role: types.RoleAdmin})
	assert.Equal(t, http.StatusOK, rr.Code)
}
