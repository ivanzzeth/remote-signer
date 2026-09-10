// Package evm_test — the signer handler's route-level tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S4)
//
// S4's last third splits SignerHandler into one function per method and
// sub-path and moves it onto r.PathValue. The questions below are about which
// request reaches which of those functions, and after the split that is decided
// by internal/api's route registration — so answering them means going through
// it.
//
// ⛔ The tempting way — build an http.ServeMux in the fixture and register
// "/api/v1/evm/signers" and friends by hand — creates a second source of truth
// for the route table. It drifts from the production registration silently: the
// tests stay green while exercising routes the daemon does not serve. So the
// patterns come from api.signersModule's Routes(), reached through the exported
// api.Module / api.RouteRegistrar pair, and no pattern is written down here
// except in the one test whose subject *is* the pattern list.
//
// ⚠️ Which is why this is `package evm_test` and not `package evm`: internal/api
// imports internal/api/handler/evm, so an in-package test file cannot import
// internal/api back — that is an import cycle. An external test package can,
// because nothing imports it.
//
// ⚠️ What these tests do NOT exercise: the middleware chain. The routes register
// as Permitted(...), whose chain begins with AuthMiddleware, which refuses any
// request lacking X-API-Key-ID / X-Timestamp / X-Signature
// (middleware/auth.go:62-69). The tests inject an API key through the request
// context instead, as the signer family always has. So the test registrar drops
// the RouteAuth it is handed and registers the bare handler: what is under test
// is dispatch. ⛔ Do not read a green run here as evidence that a signer route
// is correctly permissioned — four of them are mutating endpoints sitting on
// read_signers, which module_signers.go records in writing and
// scripts/lib/arch-baseline/ast/route-mutating-perm.txt ratchets.
//
// ⚠️ The mux these tests build has no /api/v1/ fallback in it, so an unclaimed
// path gets the *mux's* own 404 and a wrong verb on a claimed path gets the
// mux's own 405. A daemon answers differently — "/api/v1/" matches every path
// and every method, so both land on the JSON 404 fallback instead. That
// difference is measured, not assumed, in internal/api's
// TestAPIFallback_SignerStrandedPaths.
package evm_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const signerRouteAddr = "0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd"

// ---------- fixtures ----------

// signerActionSpy records whether a state change actually happened.
//
// ⛔ It is the whole point of TestSignerRoutes_StateChangeRequiresPost: a
// handler that mutates and *then* writes 405 passes a status-only assertion.
// The two methods it overrides both return success, so if a request reaches
// them the test's other arm (POST works) proves the fixture was capable and the
// refusal arm proves it was refused before doing anything.
type signerActionSpy struct {
	*evm.MockSignerManager
	unlocked bool
	locked   bool
	deleted  bool
}

func (s *signerActionSpy) UnlockSigner(_ context.Context, address, _ string) (*types.SignerInfo, error) {
	s.unlocked = true
	return &types.SignerInfo{Address: address, Type: "keystore", Enabled: true}, nil
}

func (s *signerActionSpy) LockSigner(_ context.Context, address string) (*types.SignerInfo, error) {
	s.locked = true
	return &types.SignerInfo{Address: address, Type: "keystore", Enabled: true, Locked: true}, nil
}

func (s *signerActionSpy) DeleteSigner(_ context.Context, _ string) error {
	s.deleted = true
	return nil
}

// ListSigners answers rather than erroring, because
// TestSignerRoutes_UnclaimedPathNoLongerReachesTheHandler's control arm needs
// the direct call to *succeed* — its point is that the handler serves a listing
// for a path no route claims.
func (s *signerActionSpy) ListSigners(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
	return types.SignerListResult{
		Signers: []types.SignerInfo{{Address: signerRouteAddr, Type: "keystore", Enabled: true}},
		Total:   1,
	}, nil
}

func (s *signerActionSpy) touched() bool { return s.unlocked || s.locked || s.deleted }

// signerRouteOwnerKey owns signerRouteAddr in every fixture below, so that a
// request which does reach a handler gets past the ownership check and performs
// the action. ⛔ Without that, a 405 would be indistinguishable from a 403 and
// the refusal arm would pass for the wrong reason.
func signerRouteOwnerKey() *types.APIKey {
	return &types.APIKey{ID: "signer-route-owner", Name: "Owner", Role: types.RoleAdmin, Enabled: true}
}

func newSignerRouteHandler(t *testing.T, spy *signerActionSpy) *evm.SignerHandler {
	t.Helper()
	accessSvc := evm.NewTestAccessServiceWithOwnerships(t, map[string]*types.SignerOwnership{
		signerRouteAddr: {
			SignerAddress: signerRouteAddr,
			OwnerID:       signerRouteOwnerKey().ID,
			Status:        types.SignerOwnershipActive,
		},
	})
	h, err := evm.NewSignerHandler(spy, accessSvc, slog.Default(), nil)
	require.NoError(t, err)
	return h
}

// signerMux registers the production signer routes over an otherwise empty mux.
//
// ⭐ An empty mux is deliberate: a path no signer pattern claims must reach
// nothing at all, which is exactly the property the method-less
// "/api/v1/evm/signers/" prefix could not have.
func signerMux(t *testing.T, spy *signerActionSpy) http.Handler {
	t.Helper()
	mod, err := api.NewSignersModule(newSignerRouteHandler(t, spy))
	require.NoError(t, err)
	require.NotNil(t, mod, "no module means no pattern would be registered, and every request below "+
		"would 404 for a reason that has nothing to do with what is under test")

	mux := http.NewServeMux()
	mod.Routes(muxRegistrar{mux: mux})
	return mux
}

func signerRouteRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(data)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(context.WithValue(req.Context(),
		middleware.APIKeyContextKey, signerRouteOwnerKey()))
}

// ---------- the pattern table ----------

// TestSignerRoutes_RegistersExactlyTheProductionPatterns is the one assertion
// that would notice the harness quietly registering nothing, or registering
// something else. ⚠️ It does not say these patterns are *right* — it says the
// mux the tests below drive is the mux signersModule builds, which is the only
// reason a green run here means anything about the daemon.
//
// ⛔ Its more important half is the authorization column. Seven patterns became
// eleven routes here, and five of those eleven were previously invisible inside
// one method-less prefix that declared read_signers for all of them. Splitting a
// prefix into endpoints is exactly the moment someone "fixes" a permission in
// passing — so every row states the permission the prefix or the method-scoped
// pattern it came from declared, byte for byte, and this test fails if one
// moves. Four of them (item DELETE/PATCH, access grant, access revoke) are
// mutating endpoints on a read permission; that is pre-existing debt that the
// decomposition makes *visible* for the first time, recorded in
// route-mutating-perm.txt with a written reason. ⛔ Do not close it here:
// proposal §2.5 records "the decomposition quietly changed a permission" as the
// single semantically irreversible risk in this plan — too strict shows up in
// e2e, too loose does not — so it belongs in its own PR, argued on its own.
func TestSignerRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	mod, err := api.NewSignersModule(newSignerRouteHandler(t, &signerActionSpy{MockSignerManager: newDefaultMockSignerManager()}))
	require.NoError(t, err)
	require.NotNil(t, mod)

	const read = " → permitted(read_signers)"
	const create = " → permitted(create_signers)"

	var got []string
	mod.Routes(recordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got = append(got, pattern+" → "+auth.String())
	}})

	// ⚠️ Order is the registration order, not sorted: a module registering the
	// same set in a different order is a different edit and worth seeing.
	assert.Equal(t, []string{
		"GET /api/v1/evm/signers" + read,
		"POST /api/v1/evm/signers" + create,
		"DELETE /api/v1/evm/signers/{address}" + read,
		"PATCH /api/v1/evm/signers/{address}" + read,
		"POST /api/v1/evm/signers/{address}/unlock" + read,
		"POST /api/v1/evm/signers/{address}/lock" + read,
		"POST /api/v1/evm/signers/{address}/approve" + read,
		"POST /api/v1/evm/signers/{address}/transfer" + read,
		"GET /api/v1/evm/signers/{address}/access" + read,
		"POST /api/v1/evm/signers/{address}/access" + read,
		"DELETE /api/v1/evm/signers/{address}/access/{keyID}" + read,
	}, got)
	assert.Equal(t, "signers", mod.Name())
}

// ---------- the 6d30ba1 regression, restated as a routing property ----------

// TestSignerRoutes_StateChangeRequiresPost is the regression test for the defect
// fixed in 6d30ba1, rewritten to assert the same property through the routes
// rather than through an in-handler guard.
//
// ⛔ What was wrong: `/api/v1/evm/signers/` was registered with no method, so it
// matched every verb. Go's ServeMux answers 405 only when a pattern matches the
// path and *no* pattern matches the method — with a method-less prefix in the
// table there is always a match, so 405 never happened. A GET to
// .../{address}/unlock fell through to HandleSignerAction, which read the action
// out of the path and unlocked the signer; DELETE .../{address}/approve approved
// one. On a daemon holding private keys.
//
// ⚠️ Why it moved out of signer_action_test.go: 6d30ba1 stated the rule as an
// explicit `signerActionMethods` check inside the handler, and this test asserted
// that check. The decomposition removes both the check and HandleSignerAction,
// because the rule is now stated where the mux enforces it — the four actions are
// POST-only patterns and nothing else claims their paths. Asserting it by calling
// an endpoint function directly would be asserting a check this layer no longer
// owns and should not own. So it drives the production patterns instead.
//
// ⚠️ Asserting the status code alone would be a weak test: a handler that mutates
// and *then* writes 405 would pass it. So each case asserts both that no signer
// pattern claims the request at all and that the signer manager was never
// touched. ⭐ The first of those is new and is what "structural" means: before,
// the best that could be said was that a handler refused; now there is nothing
// for the request to reach.
func TestSignerRoutes_StateChangeRequiresPost(t *testing.T) {
	for _, action := range []string{"unlock", "lock", "approve", "transfer"} {
		for _, method := range []string{
			http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodPatch,
		} {
			t.Run(method+" "+action, func(t *testing.T) {
				spy := &signerActionSpy{MockSignerManager: newDefaultMockSignerManager()}
				mux := signerMux(t, spy)

				target := "/api/v1/evm/signers/" + signerRouteAddr + "/" + action
				req := signerRouteRequest(t, method, target,
					map[string]string{"password": "secret123", "new_owner_id": "someone-else"})

				// ⭐ The structural half: ask the mux which pattern it would
				// dispatch to. Before the decomposition the answer was
				// "/api/v1/evm/signers/" and the request was served.
				if h, pattern := http.NewServeMux().Handler(req); h != nil && pattern != "" {
					t.Fatalf("premise broken: an empty mux claims %q", pattern)
				}
				_, pattern := mux.(*http.ServeMux).Handler(req)
				assert.Empty(t, pattern,
					"⛔ %s %s resolves to pattern %q — some signer route still claims a verb it does not serve",
					method, target, pattern)

				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)

				assert.Equal(t, http.StatusMethodNotAllowed, rec.Code,
					"%s on a state-changing action must be refused; only POST performs it", method)
				assert.False(t, spy.touched(),
					"⛔ %s %s reached the signer manager — the state change happened. "+
						"Refusing after mutating is not refusing.", method, action)
			})
		}
	}
}

// TestSignerRoutes_PostStillPerformsTheAction is the other half: the routing
// must not have broken the verb that is supposed to work. ⛔ Without it,
// deleting the four actions outright would make the test above pass.
func TestSignerRoutes_PostStillPerformsTheAction(t *testing.T) {
	for _, tc := range []struct {
		action  string
		body    interface{}
		touched func(*signerActionSpy) bool
	}{
		{"unlock", map[string]string{"password": "secret123"}, func(s *signerActionSpy) bool { return s.unlocked }},
		{"lock", nil, func(s *signerActionSpy) bool { return s.locked }},
	} {
		t.Run(tc.action, func(t *testing.T) {
			spy := &signerActionSpy{MockSignerManager: newDefaultMockSignerManager()}
			mux := signerMux(t, spy)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, signerRouteRequest(t, http.MethodPost,
				"/api/v1/evm/signers/"+signerRouteAddr+"/"+tc.action, tc.body))

			assert.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
			assert.True(t, tc.touched(spy), "POST must still perform the %s", tc.action)
		})
	}
}

// TestSignerRoutes_DeleteAndPatchStillReachTheirEndpoints covers the two
// endpoints that were reachable *only* through the method-less prefix, so that
// naming them as routes is shown to have kept them working rather than merely
// stopped the wrong verbs.
func TestSignerRoutes_DeleteAndPatchStillReachTheirEndpoints(t *testing.T) {
	spy := &signerActionSpy{MockSignerManager: newDefaultMockSignerManager()}
	mux := signerMux(t, spy)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, signerRouteRequest(t, http.MethodDelete,
		"/api/v1/evm/signers/"+signerRouteAddr, nil))
	assert.Equal(t, http.StatusNoContent, rec.Code, "body=%s", rec.Body.String())
	assert.True(t, spy.deleted, "DELETE must still delete the signer")

	// PATCH reaches its endpoint: the body is rejected by the handler's own
	// validation, which is only reachable if dispatch worked.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, signerRouteRequest(t, http.MethodPatch,
		"/api/v1/evm/signers/"+signerRouteAddr, map[string]interface{}{}))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "at least one of display_name or tags is required")
}

// TestSignerRoutes_UnclaimedPathsReachNoHandler replaces
// TestHandleSignerAction_InvalidPath and TestHandleSignerAction_UnknownAction,
// which asserted HandleSignerAction's own path parsing: "/api/v1/evm/signers/"
// answered 400 "invalid path: expected …", and ".../{address}/foobar" answered
// 400 "unknown action: foobar". Neither message exists any more, because the
// parsing that produced them does not — so the question they asked ("what does
// the handler say about this path") is replaced by the stronger one it was
// standing in for: which handler does this path reach? None.
//
// ⚠️ The last row is the one that used to be
// TestB3HandleRevokeAccess_NoKeyInPath: DELETE on .../access with no key id
// answered 400 "api_key_id is required in path", a guard that only existed
// because a prefix let a request with no key id reach a handler. A {keyID}
// wildcard does not match an empty segment, so the request is now refused by the
// mux — 405 rather than 404, because GET and POST are registered on that path.
func TestSignerRoutes_UnclaimedPathsReachNoHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"no address at all", http.MethodPost, "/api/v1/evm/signers/", http.StatusNotFound},
		{"unknown action", http.MethodPost, "/api/v1/evm/signers/" + signerRouteAddr + "/foobar", http.StatusNotFound},
		{"a signer with a trailing slash", http.MethodDelete, "/api/v1/evm/signers/" + signerRouteAddr + "/", http.StatusNotFound},
		{"deeper than any endpoint", http.MethodGet, "/api/v1/evm/signers/" + signerRouteAddr + "/access/k-1/extra", http.StatusNotFound},
		{"a sibling namespace", http.MethodGet, "/api/v1/evm/signers-archive", http.StatusNotFound},
		{"a verb the collection does not serve", http.MethodPut, "/api/v1/evm/signers", http.StatusMethodNotAllowed},
		{"revoke with no key id in the path", http.MethodDelete, "/api/v1/evm/signers/" + signerRouteAddr + "/access", http.StatusMethodNotAllowed},
		{"read one signer, which no route serves", http.MethodGet, "/api/v1/evm/signers/" + signerRouteAddr, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &signerActionSpy{MockSignerManager: newDefaultMockSignerManager()}
			mux := signerMux(t, spy)

			req := signerRouteRequest(t, tc.method, tc.target, nil)
			_, pattern := mux.(*http.ServeMux).Handler(req)
			assert.Empty(t, pattern,
				"%s %s resolves to %q — a signer pattern is claiming more than one endpoint's worth of paths",
				tc.method, tc.target, pattern)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, tc.want, rec.Code)
			assert.False(t, spy.touched(), "%s %s reached the signer manager", tc.method, tc.target)
		})
	}
}

// TestSignerRoutes_UnclaimedPathNoLongerReachesTheHandler is the evidence that
// the move actually changed something, run as a controlled pair: the same
// request dispatched directly at the endpoint function and dispatched through
// the mux.
//
// ⭐ ListSigners never looks at the path, so called directly it answers 200 with
// a signer listing for *any* path whatsoever, including one no signer route
// claims. That is what the whole signer family was doing before the move:
// asserting a status code the URL had no influence over.
//
// ⚠️ The `direct` arm is the control, not the harness. Delete it and this test
// degrades to "a 404 came back", which a mux with no routes at all would also
// satisfy.
func TestSignerRoutes_UnclaimedPathNoLongerReachesTheHandler(t *testing.T) {
	const unclaimed = "/api/v1/evm/signers-archive"

	spy := &signerActionSpy{MockSignerManager: newDefaultMockSignerManager()}
	h := newSignerRouteHandler(t, spy)
	mux := signerMux(t, spy)

	direct := httptest.NewRecorder()
	h.ListSigners(direct, signerRouteRequest(t, http.MethodGet, unclaimed, nil))
	require.Equal(t, http.StatusOK, direct.Code,
		"premise of this test: called directly, the handler serves %s as though it were /api/v1/evm/signers. "+
			"If that stops being true the control arm is gone and the routed arm proves nothing on its own", unclaimed)
	require.Contains(t, direct.Body.String(), `"signers"`)

	routed := httptest.NewRecorder()
	mux.ServeHTTP(routed, signerRouteRequest(t, http.MethodGet, unclaimed, nil))
	assert.Equal(t, http.StatusNotFound, routed.Code,
		"%s is claimed by no signer pattern, so it must reach no signer handler", unclaimed)
	assert.NotContains(t, routed.Body.String(), `"signers"`,
		"the mux answered, but with the handler's listing — a pattern is claiming more than it should")
}

// TestSignerRoutes_PathValueCarriesTheAddress pins the second half of the
// decomposition (proposal §1.3): the {address} wildcard used to be decorative —
// registered on four patterns while the handler cut r.URL.Path itself, so the
// same function stayed reachable from the prefix. Reading it through
// r.PathValue is what makes a matching pattern the only way in.
func TestSignerRoutes_PathValueCarriesTheAddress(t *testing.T) {
	spy := &signerActionSpy{MockSignerManager: newDefaultMockSignerManager()}
	mux := signerMux(t, spy)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, signerRouteRequest(t, http.MethodPost,
		"/api/v1/evm/signers/"+signerRouteAddr+"/unlock", map[string]string{"password": "secret123"}))

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	// The mock echoes the address it was handed back into the response, so the
	// address surviving the round trip is the wildcard being read.
	assert.Contains(t, rec.Body.String(), signerRouteAddr,
		"the address in the response is not the one in the path — {address} is not reaching the handler")
	assert.True(t, spy.unlocked)
}
