// Package evm_test — this file holds the sign-request route tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S7)
//
// S7 deleted the inline closure in setupRoutes that served
// "/api/v1/evm/requests/" — one method-less prefix, a strings.HasSuffix ladder,
// four handlers behind it — and replaced it with six named route patterns
// (internal/api/module_requests.go). The questions below are about which request
// reaches which handler, and after the change that is decided by internal/api's
// route registration, so answering them means going through it.
//
// ⛔ The tempting way — build an http.ServeMux in the fixture and register
// "/api/v1/evm/requests/{id}" and friends by hand — creates a second source of
// truth for the route table. It drifts from the production registration silently:
// the tests stay green while exercising routes the daemon does not serve. So the
// patterns come from api.requestsModule's Routes(), reached through the exported
// api.Module / api.RouteRegistrar pair, and they are written down here only in the
// one test whose subject *is* the pattern list.
//
// ⚠️ Which is why this is `package evm_test`: internal/api imports
// internal/api/handler/evm, so an in-package test file cannot import internal/api
// back — that is an import cycle. The cost is that these tests can only use
// exported identifiers, which is what evm.RequestRouteFixture (in
// request_fixture_test.go, `package evm`) exists for.
//
// ⚠️ What these tests do NOT exercise: the middleware chain. Four of the six
// routes register as Permitted(...) and two as AuthenticatedOnly(...), and every
// one of those chains begins with AuthMiddleware, which refuses a request lacking
// X-API-Key-ID / X-Timestamp / X-Signature (middleware/auth.go:62-69). These tests
// inject an API key through the request context instead, as the request family
// always has. So the test registrar drops the RouteAuth it is handed and registers
// the bare handler: what is under test is dispatch. ⛔ Do not read a green run here
// as evidence that these routes are correctly permissioned — two of them carry no
// permission at all, which module_requests.go records in writing and
// scripts/lib/arch-baseline/ast/route-auth-exemptions.txt ratchets.
//
// ⚠️ The mux these tests build holds only the module's own routes — no
// "/api/v1/evm/requests/" prefix (there is none any more) and no /api/v1/ fallback
// — so an unclaimed path gets the mux's own 404 or 405. ⛔ A daemon answers
// differently: "/api/v1/" matches every path and every method, so every stranded
// shape lands on the JSON 404 fallback instead. That difference is measured, not
// assumed, in api.TestAPIFallback_RequestStrandedPaths.
package evm_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// requestsModuleFor builds the production module around the fixture's handlers.
// ⚠️ withSimulation says whether the optional simulation handler is wired, because
// that is a production variable: setupRoutes builds one only when both
// RequestSimulationRepo and RequestRepo are configured.
func requestsModuleFor(t *testing.T, fx *evm.RequestRouteFixture, withSimulation bool) api.Module {
	t.Helper()
	sim := fx.Simulation
	if !withSimulation {
		sim = nil
	}
	mod, err := api.NewRequestsModule(fx.List, fx.Detail, fx.Approval, fx.Batch, fx.Preview, sim)
	require.NoError(t, err)
	require.NotNil(t, mod, "no module means no pattern would be registered, and every request below "+
		"would 404 for a reason that has nothing to do with what is under test")
	return mod
}

// requestMux registers the production request routes over an otherwise empty mux.
//
// ⭐ An empty mux is deliberate: a path the patterns do not claim must reach
// nothing at all, which is exactly the property the "/api/v1/evm/requests/" prefix
// could not have.
func requestMux(t *testing.T, fx *evm.RequestRouteFixture) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	requestsModuleFor(t, fx, true).Routes(muxRegistrar{mux: mux})
	return mux
}

func requestPatterns(t *testing.T, fx *evm.RequestRouteFixture, withSimulation bool) []string {
	t.Helper()
	var patterns []string
	requestsModuleFor(t, fx, withSimulation).Routes(recordingRegistrar{
		record: func(pattern string, _ api.RouteAuth) { patterns = append(patterns, pattern) },
	})
	return patterns
}

func doRequestRouteRequest(t *testing.T, mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, evm.RequestRouteAdminKey()))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestRequestRoutes_RegistersExactlyTheProductionPatterns is the assertion that
// keeps a decomposition from quietly changing authorization.
//
// ⛔ It asserts every pattern *and* its RouteAuth. Two of the six permissions were
// installed by hand inside the closure (middleware.RequirePermission around the
// approve and preview-rule branches) and two of the endpoints had no permission at
// all, inheriting the prefix's exemption; this test and route-perm-binding /
// route-auth-exempt are the only things that would notice a change.
// Negatively verified: swapping any one permission, or turning either exemption
// into a Permitted route, reddens both.
//
// ⚠️ Read the two exemption rows deliberately. They carry no permission because
// the decision is per-row — which is a real limit of a route table, not a gap
// somebody forgot — and the two reasons say so, including the one thing that
// splitting the prefix's reason revealed: the detail endpoint answers 403 for a
// foreign id while the simulation endpoint answers 404. ⛔ Making them agree is a
// decision about id enumeration and its own PR.
func TestRequestRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	fx := evm.NewRequestRouteFixture(t)

	got := map[string]string{}
	requestsModuleFor(t, fx, true).Routes(recordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got[pattern] = auth.Mode()
		if perm, ok := auth.Permission(); ok {
			got[pattern] = "permitted(" + string(perm) + ")"
		}
	}})

	assert.Equal(t, map[string]string{
		"GET /api/v1/evm/requests":                    "permitted(list_own_requests)",
		"GET /api/v1/evm/requests/{id}":               "authenticated-only",
		"POST /api/v1/evm/requests/{id}/approve":      "permitted(approve_request)",
		"POST /api/v1/evm/requests/{id}/preview-rule": "permitted(preview_rule)",
		"POST /api/v1/evm/requests/batch-approve":     "permitted(approve_request)",
		"GET /api/v1/evm/requests/{id}/simulation":    "authenticated-only",
	}, got, "⛔ the requests module registers exactly these six routes, each with the authorization the "+
		"prefix or the closure gave it; changing either is a security decision, not a refactor (proposal §2.5)")

	mod := requestsModuleFor(t, fx, true)
	assert.Equal(t, "requests", mod.Name())
}

// TestRequestRoutes_ExemptionsCarryTheirWrittenReason pins the *reasons*, not just
// the mode. ⛔ AuthenticatedOnly("") does not compile and an empty reason panics at
// startup, but a reason that says nothing would pass both — and a reason nobody can
// disagree with is the same as no reason (route_auth.go). So this asserts that each
// exemption still says which endpoint's per-row check stands in for the permission.
func TestRequestRoutes_ExemptionsCarryTheirWrittenReason(t *testing.T) {
	fx := evm.NewRequestRouteFixture(t)

	reasons := map[string]string{}
	requestsModuleFor(t, fx, true).Routes(recordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		if auth.Exempt() {
			reasons[pattern] = auth.Reason()
		}
	}})

	require.Len(t, reasons, 2, "exactly two request routes carry no permission")
	assert.Contains(t, reasons["GET /api/v1/evm/requests/{id}"], "403 for a foreign id",
		"the detail endpoint's reason must keep saying that it answers 403, which is what makes the "+
			"disagreement with the simulation endpoint visible rather than buried")
	assert.Contains(t, reasons["GET /api/v1/evm/requests/{id}/simulation"], "404 — not 403",
		"the simulation endpoint's reason must keep saying why it answers 404: id enumeration")
}

// TestRequestRoutes_SimulationRouteIsConditional pins the one production variable
// in this module's route list.
//
// ⚠️ setupRoutes builds no RequestSimulationHandler unless RouterConfig carries
// both RequestSimulationRepo and RequestRepo — e2e/test_server.go sets neither — so
// a deployment without them serves five routes, not six. ⛔ The alternative
// (register it always, 404 inside) would put a route in the table that such a
// daemon does not serve, which is the "reading setupRoutes cannot tell you what is
// served" problem the module shape exists to remove.
func TestRequestRoutes_SimulationRouteIsConditional(t *testing.T) {
	fx := evm.NewRequestRouteFixture(t)

	with := requestPatterns(t, fx, true)
	without := requestPatterns(t, fx, false)

	assert.Len(t, with, 6)
	assert.Len(t, without, 5)
	assert.NotContains(t, without, "GET /api/v1/evm/requests/{id}/simulation",
		"with no simulation handler the route must be absent, so the path reaches the /api/v1/ JSON 404")
	assert.Contains(t, with, "GET /api/v1/evm/requests/{id}/simulation")
}

// TestRequestRoutes_EveryEndpointIsReachable walks the production pattern list and
// drives each route once, so that a route registered but wired to the wrong
// handler, or an {id} a handler reads under another name, fails by name.
//
// ⛔ The pattern list is not written here — it comes from Routes(). A literal list
// would be the second route table this file exists to avoid.
func TestRequestRoutes_EveryEndpointIsReachable(t *testing.T) {
	fx := evm.NewRequestRouteFixture(t)
	patterns := requestPatterns(t, fx, true)
	require.Len(t, patterns, 6, "the rows below would pass for the wrong reason if the module registered "+
		"a different number of routes")

	// A body good enough that no endpoint stops at "invalid request body"; each
	// endpoint may still refuse for its own reasons, which is why the assertion
	// below is about *not* being unrouted rather than about a status.
	const body = `{"approved":true,"rule_type":"evm_address_list","rule_mode":"whitelist","request_ids":["` +
		evm.RequestRouteID + `"]}`

	for _, pattern := range patterns {
		method, path, ok := strings.Cut(pattern, " ")
		require.True(t, ok, "pattern %q has no method — every request route is method-scoped", pattern)

		target := strings.ReplaceAll(path, "{id}", evm.RequestRouteID)
		require.NotContains(t, target, "{", "pattern %q has a wildcard this test does not know how to fill", pattern)

		t.Run(pattern, func(t *testing.T) {
			fx := evm.NewRequestRouteFixture(t)
			mux := requestMux(t, fx)

			rr := doRequestRouteRequest(t, mux, method, target, body)
			// ⭐ 404 and 405 are the two answers a bare mux gives when nothing
			// matched. Any other status means a handler ran, which is all this row
			// claims — each endpoint's own behaviour is the subject of the
			// handler-package tests.
			assert.NotEqual(t, http.StatusNotFound, rr.Code,
				"%s reached no handler: body %s", pattern, rr.Body.String())
			assert.NotEqual(t, http.StatusMethodNotAllowed, rr.Code,
				"%s reached no handler: body %s", pattern, rr.Body.String())
		})
	}
}

// TestRequestRoutes_IdComesFromTheWildcard pins the PathValue plumbing on the three
// routes that have an {id}: the response echoes the id, so an id read from the
// wrong place shows up as a wrong echo rather than as a generic 404.
func TestRequestRoutes_IdComesFromTheWildcard(t *testing.T) {
	t.Run("detail", func(t *testing.T) {
		fx := evm.NewRequestRouteFixture(t)
		mux := requestMux(t, fx)
		rr := doRequestRouteRequest(t, mux, http.MethodGet, "/api/v1/evm/requests/"+evm.RequestRouteID, "")
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

		var resp map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, evm.RequestRouteID, resp["id"], "the id must come from {id}")
		assert.Equal(t, []string{evm.RequestRouteID}, fx.Fetched())
	})

	t.Run("approve", func(t *testing.T) {
		fx := evm.NewRequestRouteFixture(t)
		mux := requestMux(t, fx)
		rr := doRequestRouteRequest(t, mux, http.MethodPost,
			"/api/v1/evm/requests/"+evm.RequestRouteID+"/approve", `{"approved":true}`)
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
		assert.Equal(t, []string{evm.RequestRouteID}, fx.Approved(),
			"the approved row must be the one {id} named")
	})

	t.Run("preview-rule", func(t *testing.T) {
		fx := evm.NewRequestRouteFixture(t)
		mux := requestMux(t, fx)
		rr := doRequestRouteRequest(t, mux, http.MethodPost,
			"/api/v1/evm/requests/"+evm.RequestRouteID+"/preview-rule",
			`{"rule_type":"evm_address_list","rule_mode":"whitelist"}`)
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
		assert.Equal(t, []string{evm.RequestRouteID}, fx.Previewed())
	})

	t.Run("simulation", func(t *testing.T) {
		fx := evm.NewRequestRouteFixture(t)
		mux := requestMux(t, fx)
		rr := doRequestRouteRequest(t, mux, http.MethodGet,
			"/api/v1/evm/requests/"+evm.RequestRouteID+"/simulation", "")
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
		assert.Equal(t, []string{evm.RequestRouteID}, fx.SimulationsRead())
	})
}

// TestRequestRoutes_ExtraDepthNoLongerApprovesAnotherRow is the one defect this step
// closes, and the reason it is its own test rather than a row in the table below.
//
// ⛔ Measured before the change, against the real registrations: the prefix matched
// any depth, the closure picked the approval handler by
// strings.HasSuffix(path, "/approve"), and the handler read the id as
// parts[len-2] — so POST /api/v1/evm/requests/a/b/approve answered 200 and
// **approved request "b"**, and .../a/b/c/d/approve approved "d". Every segment in
// front of the id was accepted and thrown away, on an endpoint that mutates: the
// path a caller (and the audit log) sees names a different row than the one that
// changed. It is not a permission bypass — the closure did install
// approve_request, and the method was checked — which is why it is an id/path
// confusion rather than an escalation.
//
// ⭐ The assertion is the effect, not the status: Approved() must stay empty.
func TestRequestRoutes_ExtraDepthNoLongerApprovesAnotherRow(t *testing.T) {
	for _, tc := range []struct {
		name, path, approvedBefore string
	}{
		{"two segments, which approved \"b\"", "/api/v1/evm/requests/a/b/approve", "b"},
		{"four segments, which approved \"d\"", "/api/v1/evm/requests/a/b/c/d/approve", "d"},
		{"no id at all, which approved \"requests\"", "/api/v1/evm/requests/approve", "requests"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRequestRouteFixture(t)
			mux := requestMux(t, fx)

			rr := doRequestRouteRequest(t, mux, http.MethodPost, tc.path, `{"approved":true}`)
			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code,
				"POST %s reached a handler: %d %s", tc.path, rr.Code, rr.Body.String())
			assert.Empty(t, fx.Approved(),
				"⛔ this used to approve request %q — and the effect is the assertion that matters, "+
					"not the status", tc.approvedBefore)
			assert.False(t, fx.Touched(), "⛔ nothing ran at all")

			// ⭐ Control arm: the same verb and body against the canonical path does
			// reach the handler and does approve. Without it a green run above could
			// mean the fixture was incapable rather than that routing refused the
			// deep form.
			ctl := evm.NewRequestRouteFixture(t)
			ctlRR := doRequestRouteRequest(t, requestMux(t, ctl), http.MethodPost,
				"/api/v1/evm/requests/"+evm.RequestRouteID+"/approve", `{"approved":true}`)
			require.Equal(t, http.StatusOK, ctlRR.Code, "control arm body: %s", ctlRR.Body.String())
			require.Equal(t, []string{evm.RequestRouteID}, ctl.Approved(), "control arm must really approve")
		})
	}
}

// TestRequestRoutes_UnclaimedShapesReachNoEndpoint replaces the seven guard tests
// the decomposition removed — TestApprovalHandler_MethodNotAllowed,
// TestPreviewRuleHandler_MethodNotAllowed, TestRequestHandler_MethodNotAllowed,
// TestListHandler_MethodNotAllowed, TestRequestSimulationHandler_NonGET,
// TestB3ListHandler_MethodNotAllowed, TestB3RequestSimulation_MethodNotAllowed —
// plus the two "invalid path" tests (TestB3RequestHandler_InvalidPath,
// TestB3RequestSimulation_InvalidPath) and the depth and trailing-slash shapes
// nothing ever asserted.
//
// ⭐ Strictly stronger than what it replaces: those tests asserted a status from a
// handler's own guard. The guards are gone because no pattern routes those verbs or
// shapes anywhere, so this drives the production pattern set, asserts the mux
// resolved *no* route, and asserts nothing ran — which a status-only check would
// not catch in a handler that mutated first and refused afterwards.
//
// ⛔ And read the verb rows for what they are. On presets, signers and hd-wallets
// the equivalent rows were live defects (a GET that applied a preset, unlocked a
// signer, ran a derivation). Here they were not: all four closure branches checked
// their method, measured with spies on ProcessApproval and PreviewRuleForRequest —
// every wrong verb answered 405 and called neither. What changes is that the guard
// is now unrepresentable rather than merely written down. The *depth* rows are the
// ones that were defects; see the test above.
func TestRequestRoutes_UnclaimedShapesReachNoEndpoint(t *testing.T) {
	id := evm.RequestRouteID

	for _, tc := range []struct{ name, method, path string }{
		// ---- verbs no route declares (the seven removed guard tests) ----
		{"PUT on the collection", http.MethodPut, "/api/v1/evm/requests"},
		{"POST on the collection", http.MethodPost, "/api/v1/evm/requests"},
		{"DELETE on the collection", http.MethodDelete, "/api/v1/evm/requests"},
		{"POST on an item", http.MethodPost, "/api/v1/evm/requests/" + id},
		{"DELETE on an item", http.MethodDelete, "/api/v1/evm/requests/" + id},
		{"GET on approve", http.MethodGet, "/api/v1/evm/requests/" + id + "/approve"},
		{"DELETE on approve", http.MethodDelete, "/api/v1/evm/requests/" + id + "/approve"},
		{"GET on preview-rule", http.MethodGet, "/api/v1/evm/requests/" + id + "/preview-rule"},
		{"POST on simulation", http.MethodPost, "/api/v1/evm/requests/" + id + "/simulation"},
		{"DELETE on simulation", http.MethodDelete, "/api/v1/evm/requests/" + id + "/simulation"},

		// ⚠️ GET /api/v1/evm/requests/batch-approve is deliberately NOT here, and
		// measuring it is what removed it: "batch-approve" is a legal single
		// segment, so that request matches GET /api/v1/evm/requests/{id} and reads
		// a request whose id is "batch-approve" — exactly what the closure's
		// default branch did with it. Unchanged behaviour (404 "request not found"
		// against a real repository), not a stranded shape; see
		// TestRequestRoutes_BatchApproveIsOnlyALiteralForPost.

		// ---- trailing slash ----
		// ⚠️ The prefix forgave all of these in the *reading* direction: the
		// collection-with-a-slash and item-with-a-slash both reached the detail
		// handler with an empty id (404 against a real repository), and a trailing
		// slash after an action fell out of the suffix ladder into the same place.
		{"the collection with a trailing slash", http.MethodGet, "/api/v1/evm/requests/"},
		{"an item with a trailing slash", http.MethodGet, "/api/v1/evm/requests/" + id + "/"},
		{"approve with a trailing slash", http.MethodPost, "/api/v1/evm/requests/" + id + "/approve/"},
		{"preview-rule with a trailing slash", http.MethodPost, "/api/v1/evm/requests/" + id + "/preview-rule/"},
		{"simulation with a trailing slash", http.MethodGet, "/api/v1/evm/requests/" + id + "/simulation/"},
		{"batch-approve with a trailing slash", http.MethodPost, "/api/v1/evm/requests/batch-approve/"},

		// ---- extra depth, which the prefix swallowed ----
		// ⚠️ Reads rather than writes, so these were wrong answers rather than wrong
		// mutations: "the last segment wins" meant a deep path answered with
		// whatever request the final segment named.
		{"a deep path, which answered with request \"c\"", http.MethodGet, "/api/v1/evm/requests/a/b/c"},
		{"an unknown sub-action, which answered with request \"unknown\"", http.MethodGet, "/api/v1/evm/requests/" + id + "/unknown"},
		{"preview-rule two segments deep, which previewed \"b\"", http.MethodPost, "/api/v1/evm/requests/a/b/preview-rule"},
		{"simulation two segments deep", http.MethodGet, "/api/v1/evm/requests/a/b/simulation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRequestRouteFixture(t)
			mux := requestMux(t, fx)

			rr := doRequestRouteRequest(t, mux, tc.method, tc.path,
				`{"approved":true,"rule_type":"evm_address_list","rule_mode":"whitelist","request_ids":["`+id+`"]}`)

			// ⚠️ 404 or 405: a bare mux answers 405 when a sibling method is
			// registered on the very same path and 404 otherwise. ⛔ Which one it is
			// says nothing a client can rely on — a daemon answers the /api/v1/
			// fallback's 404 for every row here, which is
			// api.TestAPIFallback_RequestStrandedPaths' subject. What matters is that
			// no endpoint ran.
			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code,
				"%s %s reached a handler: %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
			assert.Empty(t, fx.Approved(), "⛔ nothing was approved")
			assert.False(t, fx.Touched(),
				"⛔ nothing ran — not the approval, not the preview, not either read; this is the "+
					"assertion that matters, not the status")
		})
	}
}

// TestRequestRoutes_HeadOnTheReadsIsAWidening pins the two answers that got *more*
// permissive, so that they are a recorded decision rather than a surprise.
//
// ⚠️ Go's mux matches HEAD against a GET pattern and net/http drops the body, so
// HEAD now reaches ListHandler and RequestHandler where their own method guards
// answered 405 (the collection was registered without a method at all). Both
// endpoints are pure reads. The same widening happened to settings in S5 and to
// presets and templates in S6; it is listed in module_requests.go's table.
func TestRequestRoutes_HeadOnTheReadsIsAWidening(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"the collection", "/api/v1/evm/requests"},
		{"one request", "/api/v1/evm/requests/" + evm.RequestRouteID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRequestRouteFixture(t)
			mux := requestMux(t, fx)

			rr := doRequestRouteRequest(t, mux, http.MethodHead, tc.path, "")
			assert.Equal(t, http.StatusOK, rr.Code,
				"HEAD now reaches the read endpoint; it used to be the handler's own 405")
		})
	}
}

// TestRequestRoutes_BatchApproveIsOnlyALiteralForPost pins the one overlap in this
// pattern set, because Go's mux resolving it the right way is a property rather
// than an obvious fact.
//
// ⚠️ "POST /api/v1/evm/requests/batch-approve" and
// "GET /api/v1/evm/requests/{id}" both match a request for
// /api/v1/evm/requests/batch-approve; the literal segment is a strict subset of
// the wildcard, so the mux registers both without panicking and prefers the
// literal for POST. The GET falls to the item route with id "batch-approve",
// which is what the closure's default branch did with it too — unchanged, and 404
// "request not found" against a real repository.
func TestRequestRoutes_BatchApproveIsOnlyALiteralForPost(t *testing.T) {
	fx := evm.NewRequestRouteFixture(t)
	mux := requestMux(t, fx)

	rr := doRequestRouteRequest(t, mux, http.MethodGet, "/api/v1/evm/requests/batch-approve", "")
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	assert.Equal(t, []string{"batch-approve"}, fx.Fetched(),
		"a GET on that path is a request lookup whose id happens to be \"batch-approve\" — "+
			"the same thing the prefix's default branch made of it")
	assert.Empty(t, fx.Approved(), "⛔ and it approves nothing")
}
