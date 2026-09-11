// Package evm_test — this file holds the rule route tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S8)
//
// S8 is replacing the two method-less patterns that served rule.go's twelve
// endpoints — "/api/v1/evm/rules" and "/api/v1/evm/rules/", the latter matching
// every verb at every depth — with named route patterns
// (internal/api/module_rules.go). The questions below are about which request
// reaches which endpoint, and after the change that is decided by internal/api's
// route registration, so answering them means going through it.
//
// ⛔ The tempting way — build an http.ServeMux in the fixture and register
// "/api/v1/evm/rules/{id}/approve" and friends by hand — creates a second source
// of truth for the route table. It drifts from the production registration
// silently: the tests stay green while exercising routes the daemon does not
// serve. So the patterns come from api.rulesModule's Routes(), reached through
// the exported api.Module / api.RouteRegistrar pair, and they are written down
// here only in the one test whose subject *is* the pattern list.
//
// ⚠️ Which is why this is `package evm_test`: internal/api imports
// internal/api/handler/evm, so an in-package test file cannot import internal/api
// back — that is an import cycle. The cost is that these tests can only use
// exported identifiers, which is what evm.RuleRouteFixture (in
// rule_fixture_test.go, `package evm`) exists for.
//
// ⚠️ What these tests do NOT exercise: the middleware chain. Every rule route
// registers as Permitted(...), and that chain begins with AuthMiddleware, which
// refuses a request lacking X-API-Key-ID / X-Timestamp / X-Signature
// (middleware/auth.go:62-69). These tests inject an API key through the request
// context instead, as the rule family always has. So the test registrar drops
// the RouteAuth it is handed and registers the bare handler: what is under test
// is dispatch. ⛔ Do not read a green run here as evidence that these routes are
// correctly permissioned — every one of them carries PermListRules, which for
// the mutating ones is recorded debt, written down in module_rules.go and
// ratcheted by scripts/lib/arch-baseline/ast/route-mutating-perm.txt.
//
// ⚠️ The mux these tests build holds only the module's own routes — no
// "/api/v1/evm/rules/" prefix and no /api/v1/ fallback — so an unclaimed path
// gets the mux's own 404 or 405. ⛔ A daemon answers differently while the
// decomposition is unfinished: the prefix is still registered in setupRoutes and
// still claims every shape these patterns do not. That is stated, not assumed,
// in the behaviour table on rulesModule.Routes.
package evm_test

import (
	"bytes"
	"context"
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

func rulesModuleFor(t *testing.T, fx *evm.RuleRouteFixture) api.Module {
	t.Helper()
	return rulesModuleWith(t, fx, true)
}

// rulesModuleWith builds the production module. ⚠️ withBudgets is a production
// variable, not a test knob: setupRoutes gives RuleHandler a budget repository
// only when RouterConfig.BudgetRepo is set, and the two budget routes are
// registered on exactly that condition.
func rulesModuleWith(t *testing.T, fx *evm.RuleRouteFixture, withBudgets bool) api.Module {
	t.Helper()
	mod, err := api.NewRulesModule(fx.Handler, withBudgets)
	require.NoError(t, err)
	require.NotNil(t, mod, "no module means no pattern would be registered, and every request below "+
		"would 404 for a reason that has nothing to do with what is under test")
	return mod
}

// ruleMux registers the production rule routes over an otherwise empty mux.
//
// ⭐ An empty mux is deliberate: a path the patterns do not claim must reach
// nothing at all, which is exactly the property the "/api/v1/evm/rules/" prefix
// could not have.
func ruleMux(t *testing.T, fx *evm.RuleRouteFixture) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	rulesModuleFor(t, fx).Routes(muxRegistrar{mux: mux})
	return mux
}

func rulePatterns(t *testing.T, fx *evm.RuleRouteFixture) []string {
	t.Helper()
	var patterns []string
	rulesModuleFor(t, fx).Routes(recordingRegistrar{
		record: func(pattern string, _ api.RouteAuth) { patterns = append(patterns, pattern) },
	})
	return patterns
}

func doRuleRouteRequest(t *testing.T, mux http.Handler, method, path, body string, key any) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if key != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, key))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestRuleRoutes_RegistersExactlyTheProductionPatterns is the assertion that
// keeps a decomposition from quietly changing authorization.
//
// ⛔ It asserts every pattern *and* its permission. All of them carry
// PermListRules because that is what the prefix they came from declared — the
// ⛔ KNOWN LIMIT paragraph in route_auth.go names this exact surface ("
// /api/v1/evm/rules/ declares PermListRules for all twelve endpoints behind
// it") — and naming the routes is what lets route-perm-binding and
// route-mutating-perm see it at all. ⛔ Tightening any of them is a security
// decision with its own PR, and this test plus those two baselines are what
// would notice.
//
// ⚠️ Negatively verified: swapping any one permission reddens this test and
// route-perm-binding; turning any of them into AuthenticatedOnly reddens this
// test, route-perm-binding and route-auth-exempt.
func TestRuleRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	fx := evm.NewRuleRouteFixture(t)

	got := map[string]string{}
	rulesModuleFor(t, fx).Routes(recordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got[pattern] = auth.Mode()
		if perm, ok := auth.Permission(); ok {
			got[pattern] = "permitted(" + string(perm) + ")"
		}
	}})

	assert.Equal(t, map[string]string{
		"GET /api/v1/evm/rules":                     "permitted(list_rules)",
		"POST /api/v1/evm/rules":                    "permitted(list_rules)",
		"GET /api/v1/evm/rules/{id}":                "permitted(list_rules)",
		"PATCH /api/v1/evm/rules/{id}":              "permitted(list_rules)",
		"DELETE /api/v1/evm/rules/{id}":             "permitted(list_rules)",
		"POST /api/v1/evm/rules/{id}/approve":       "permitted(list_rules)",
		"POST /api/v1/evm/rules/{id}/reject":        "permitted(list_rules)",
		"POST /api/v1/evm/rules/{id}/propose":       "permitted(list_rules)",
		"POST /api/v1/evm/rules/validate":           "permitted(list_rules)",
		"POST /api/v1/evm/rules/{id}/validate":      "permitted(list_rules)",
		"GET /api/v1/evm/rules/{id}/budgets":        "permitted(list_rules)",
		"POST /api/v1/evm/rules/{id}/budgets/reset": "permitted(manage_budgets)",
	}, got, "⛔ the rules module registers exactly these routes, each with the authorization the prefix "+
		"gave it; changing either is a security decision, not a refactor (proposal §2.5)")

	assert.Equal(t, "rules", rulesModuleFor(t, fx).Name())
}

// TestRuleRoutes_EveryEndpointIsReachable walks the production pattern list and
// drives each route once, so that a route registered but wired to the wrong
// handler, or an {id} a handler reads under another name, fails by name.
//
// ⛔ The pattern list is not written here — it comes from Routes(). A literal
// list would be the second route table this file exists to avoid.
func TestRuleRoutes_EveryEndpointIsReachable(t *testing.T) {
	for _, pattern := range rulePatterns(t, evm.NewRuleRouteFixture(t)) {
		method, path, ok := strings.Cut(pattern, " ")
		require.True(t, ok, "pattern %q has no method — every rule route is method-scoped", pattern)

		target := strings.ReplaceAll(path, "{id}", evm.RuleRouteID)
		require.NotContains(t, target, "{", "pattern %q has a wildcard this test does not know how to fill", pattern)

		t.Run(pattern, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)
			rr := doRuleRouteRequest(t, ruleMux(t, fx), method, target,
				evm.RuleRouteProposeBody(), evm.RuleRouteAdminKey())

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

// TestRuleRoutes_IdComesFromTheWildcard pins the PathValue plumbing on all three
// routes: each one's effect is visible on the row {id} names, so an id read from
// the wrong place shows up as "the wrong row changed" rather than as a generic
// 404.
func TestRuleRoutes_IdComesFromTheWildcard(t *testing.T) {
	t.Run("approve", func(t *testing.T) {
		fx := evm.NewRuleRouteFixture(t)
		rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodPost,
			"/api/v1/evm/rules/"+evm.RuleRouteID+"/approve", "", evm.RuleRouteAdminKey())
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
		assert.Equal(t, "active", fx.RuleStatus(evm.RuleRouteID), "approve must act on the row {id} named")
	})

	t.Run("reject", func(t *testing.T) {
		fx := evm.NewRuleRouteFixture(t)
		rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodPost,
			"/api/v1/evm/rules/"+evm.RuleRouteID+"/reject", `{"reason":"no"}`, evm.RuleRouteAdminKey())
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
		assert.Equal(t, "rejected", fx.RuleStatus(evm.RuleRouteID))
	})

	t.Run("propose", func(t *testing.T) {
		fx := evm.NewRuleRouteFixture(t)
		rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodPost,
			"/api/v1/evm/rules/"+evm.RuleRouteID+"/propose", evm.RuleRouteProposeBody(), evm.RuleRouteAdminKey())
		// ⚠️ 202, not 201: a proposal is accepted for approval, not created as a
		// live rule (rule_crud.go's proposeRule).
		require.Equal(t, http.StatusAccepted, rr.Code, "body: %s", rr.Body.String())
		require.Len(t, fx.Proposals(), 1, "propose writes one proposal row")
	})
}

// TestRuleRoutes_NoVerbOrDepthReachesTheseMutations is the negative-space test
// for this slice, and ⭐ it is worth reading for what it did NOT find.
//
// On presets, signers and hd-wallets the equivalent rows were live defects (a
// GET that applied a preset, unlocked a signer, ran a derivation); on requests
// the defect was depth (POST /requests/a/b/approve approved request "b"). ⛔ On
// rules, measured the same way — against the three real registrations, with the
// repository read back after every request rather than the status — **neither
// exists**. rule.go's sub-action branches required `r.Method == http.MethodPost`
// *and* `ruleID != "" && !strings.Contains(ruleID, "/")`, and every shape that
// failed either test fell through to a 400. That second condition is the guard
// the other handlers did not have, and it is exactly what stopped the S7 defect
// from having a counterpart here.
//
// ⭐ So these rows are not holes being closed. What changes is that the guard is
// unrepresentable now rather than merely written down — and the assertion is the
// effect, not the status, because a status-only check passes for a handler that
// mutates first and refuses afterwards.
func TestRuleRoutes_NoVerbOrDepthReachesTheseMutations(t *testing.T) {
	id := evm.RuleRouteID

	for _, tc := range []struct{ name, method, path string }{
		// ---- verbs no route declares ----
		{"GET on approve", http.MethodGet, "/api/v1/evm/rules/" + id + "/approve"},
		{"DELETE on approve", http.MethodDelete, "/api/v1/evm/rules/" + id + "/approve"},
		{"PUT on approve", http.MethodPut, "/api/v1/evm/rules/" + id + "/approve"},
		{"HEAD on approve", http.MethodHead, "/api/v1/evm/rules/" + id + "/approve"},
		{"GET on reject", http.MethodGet, "/api/v1/evm/rules/" + id + "/reject"},
		{"GET on propose", http.MethodGet, "/api/v1/evm/rules/" + id + "/propose"},

		// ---- extra depth: the S7 shape, which rule.go already refused ----
		{"approve one segment deep", http.MethodPost, "/api/v1/evm/rules/a/" + id + "/approve"},
		{"approve three segments deep", http.MethodPost, "/api/v1/evm/rules/a/b/c/" + id + "/approve"},
		{"approve with the id in front", http.MethodPost, "/api/v1/evm/rules/" + id + "/x/approve"},
		{"reject one segment deep", http.MethodPost, "/api/v1/evm/rules/a/" + id + "/reject"},
		{"propose one segment deep", http.MethodPost, "/api/v1/evm/rules/a/" + id + "/propose"},

		// ---- no id at all ----
		{"approve with no id", http.MethodPost, "/api/v1/evm/rules/approve"},

		// ---- trailing slash ----
		{"approve with a trailing slash", http.MethodPost, "/api/v1/evm/rules/" + id + "/approve/"},
		{"reject with a trailing slash", http.MethodPost, "/api/v1/evm/rules/" + id + "/reject/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)

			rr := doRuleRouteRequest(t, ruleMux(t, fx), tc.method, tc.path,
				evm.RuleRouteProposeBody(), evm.RuleRouteAdminKey())

			// ⚠️ 404 or 405: a bare mux answers 405 when a sibling method is
			// registered on the very same path and 404 otherwise. ⛔ Which one it is
			// says nothing a client can rely on. What matters is that nothing ran.
			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code,
				"%s %s reached a handler: %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
			assert.Equal(t, "pending_approval", fx.RuleStatus(id),
				"⛔ the rule's status must be untouched — this is the assertion that matters, not the status code")
			assert.Empty(t, fx.Proposals(), "⛔ nothing proposed")
			assert.Equal(t, []string{id}, fx.RuleIDs(), "⛔ no row created or deleted")

			// ⭐ Control arm: the same verb and body against the canonical path does
			// reach the handler and does mutate. Without it a green run above could
			// mean the fixture was incapable rather than that routing refused.
			ctl := evm.NewRuleRouteFixture(t)
			ctlRR := doRuleRouteRequest(t, ruleMux(t, ctl), http.MethodPost,
				"/api/v1/evm/rules/"+id+"/approve", "", evm.RuleRouteAdminKey())
			require.Equal(t, http.StatusOK, ctlRR.Code, "control arm body: %s", ctlRR.Body.String())
			require.Equal(t, "active", ctl.RuleStatus(id), "control arm must really approve")
		})
	}
}

// TestRuleRoutes_EncodedSlashIdIsTheOneChangedAnswer pins the single answer this
// slice changes, so it is a recorded decision rather than a surprise.
//
// ⚠️ ServeHTTP split the *decoded* r.URL.Path, so an id sent as a%2Fb came out
// containing a '/', failed `!strings.Contains(ruleID, "/")`, fell through and
// answered 400 "invalid rule_id format". Go's mux splits the encoded path and
// decodes each segment, so {id} is now the whole "a/b" and the endpoint runs —
// answering 404 "rule not found", because no such rule can exist: rule.go's
// ruleIDPattern admits no form containing '/'. ⛔ No client can produce this
// request; checked in pkg/client, pkg/rs-client, pkg/js-client,
// extension/background.js, web/src, pkg/mcp-server and e2e/ rather than assumed.
func TestRuleRoutes_EncodedSlashIdIsTheOneChangedAnswer(t *testing.T) {
	fx := evm.NewRuleRouteFixture(t)

	rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodPost,
		"/api/v1/evm/rules/a%2Fb/approve", "", evm.RuleRouteAdminKey())

	assert.Equal(t, http.StatusNotFound, rr.Code,
		"an encoded-slash id reaches the endpoint and misses; it used to be 400 from the prefix's fallthrough")
	assert.Equal(t, "pending_approval", fx.RuleStatus(evm.RuleRouteID), "⛔ and it approves nothing")
}

// TestRuleRoutes_InHandlerRoleChecksSurvivedTheMove pins the checks that are
// *not* on the route, because a decomposition is exactly when they get lost.
//
// ⛔ approve and reject re-check apiKey.IsAdmin() inside the handler ("defense in
// depth", rule_query.go) and propose checks agent-or-admin. RouteAuth cannot
// express a role, so none of these could have become a route permission even if
// that were allowed — and it is not (proposal §2.5).
func TestRuleRoutes_InHandlerRoleChecksSurvivedTheMove(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
		want             int
	}{
		{"approve refuses a non-admin", "/api/v1/evm/rules/" + evm.RuleRouteID + "/approve", "", http.StatusForbidden},
		{"reject refuses a non-admin", "/api/v1/evm/rules/" + evm.RuleRouteID + "/reject", "", http.StatusForbidden},
		// ⚠️ propose *allows* an agent — that is its point — so the row that proves
		// the check survived is the one where it gets through to its own validation.
		{"propose admits an agent", "/api/v1/evm/rules/" + evm.RuleRouteID + "/propose", evm.RuleRouteProposeBody(), http.StatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)
			rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodPost, tc.path, tc.body, evm.RuleRouteAgentKey())
			assert.Equal(t, tc.want, rr.Code, "body: %s", rr.Body.String())
		})
	}
}

// TestRuleRoutes_UnauthenticatedIsRefusedByEveryEndpoint pins the guard that was
// easiest to drop in this move: ServeHTTP checked for an API key **once, at the
// top**, on behalf of all twelve endpoints, and five of the twelve handlers have
// no check of their own. ⛔ The named endpoints carry it individually now
// (RuleHandler.requireAPIKey), and this drives the production pattern list so a
// route added later without it fails here.
func TestRuleRoutes_UnauthenticatedIsRefusedByEveryEndpoint(t *testing.T) {
	for _, pattern := range rulePatterns(t, evm.NewRuleRouteFixture(t)) {
		method, path, ok := strings.Cut(pattern, " ")
		require.True(t, ok)
		target := strings.ReplaceAll(path, "{id}", evm.RuleRouteID)

		t.Run(pattern, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)
			rr := doRuleRouteRequest(t, ruleMux(t, fx), method, target, evm.RuleRouteProposeBody(), nil)
			assert.Equal(t, http.StatusUnauthorized, rr.Code, "body: %s", rr.Body.String())
			assert.Equal(t, "pending_approval", fx.RuleStatus(evm.RuleRouteID))
		})
	}
}

// ---------- proposal S8 slice 2: the four guarded sub-resources ----------

// TestRuleRoutes_BudgetRoutesAreConditional pins the one production variable in
// this module's route list.
//
// ⚠️ setupRoutes gives RuleHandler a budget repository only when
// RouterConfig.BudgetRepo is set, and both ServeHTTP branches that served these
// paths required it (`h.budgetRepo != nil`) before dispatching. A deployment
// without one serves five rule routes here, not seven. ⛔ The alternative —
// register them always and answer from inside — would put routes in the table
// that such a daemon does not serve, and would also change the answer: with no
// repository ResetBudgets answers its own 500, which no deployment has seen
// because the branch in front of it never let a request through.
//
// ⚠️ What a daemon without a budget repository answers for these paths does not
// change in this slice: "/api/v1/evm/rules/" is still registered, still claims
// them, and still answers 400 "invalid rule_id format" from the fallthrough —
// exactly as before. ⛔ That becomes the /api/v1/ JSON 404 when the prefix goes,
// in slice 3.
func TestRuleRoutes_BudgetRoutesAreConditional(t *testing.T) {
	fx := evm.NewRuleRouteFixture(t)

	var with, without []string
	rulesModuleWith(t, fx, true).Routes(recordingRegistrar{
		record: func(p string, _ api.RouteAuth) { with = append(with, p) }})
	rulesModuleWith(t, fx, false).Routes(recordingRegistrar{
		record: func(p string, _ api.RouteAuth) { without = append(without, p) }})

	assert.Len(t, with, 12)
	assert.Len(t, without, 10)
	assert.NotContains(t, without, "GET /api/v1/evm/rules/{id}/budgets")
	assert.NotContains(t, without, "POST /api/v1/evm/rules/{id}/budgets/reset")
	assert.Contains(t, with, "GET /api/v1/evm/rules/{id}/budgets")
	assert.Contains(t, with, "POST /api/v1/evm/rules/{id}/budgets/reset")
}

// TestRuleRoutes_ValidateAdminCheckIsStillInTheHandler is the assertion proposal
// §2.1 asked for by name.
//
// ⛔ Both validate endpoints are registered with PermListRules — the permission
// the prefix declared — and the thing that actually narrows them to admins is a
// role check *inside* the handler, copied verbatim from the ServeHTTP branch
// into RuleHandler.requireAdmin. RouteAuth cannot express a role, so this could
// not have become a route permission even if converting it were allowed, and it
// is not (proposal §2.5: a decomposition must not change who may call a route).
//
// ⚠️ The ⛔ KNOWN LIMIT section of route_auth.go names exactly this pair as the
// reason "every route declares a permission" does not mean the permissions are
// right. It is still true, and this test is what would notice if the check were
// dropped on the way through.
func TestRuleRoutes_ValidateAdminCheckIsStillInTheHandler(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"batch validate", "/api/v1/evm/rules/validate"},
		{"one rule's validate", "/api/v1/evm/rules/" + evm.RuleRouteID + "/validate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)
			mux := ruleMux(t, fx)

			agent := doRuleRouteRequest(t, mux, http.MethodPost, tc.path, "", evm.RuleRouteAgentKey())
			assert.Equal(t, http.StatusForbidden, agent.Code, "body: %s", agent.Body.String())
			assert.Contains(t, agent.Body.String(), "admin role required",
				"⛔ the handler's own wording, which is what a client sees; the route permission is list_rules")

			// ⭐ Control arm: an admin gets through, so the 403 above is the role
			// check and not the route failing to match.
			admin := doRuleRouteRequest(t, mux, http.MethodPost, tc.path, "", evm.RuleRouteAdminKey())
			assert.NotEqual(t, http.StatusForbidden, admin.Code, "body: %s", admin.Body.String())
			assert.NotEqual(t, http.StatusNotFound, admin.Code, "body: %s", admin.Body.String())
		})
	}
}

// TestRuleRoutes_BudgetIdLengthGuardSurvivedTheMove pins the one guard {id} does
// not reproduce.
//
// ⚠️ Both budget branches required `len(ruleID) <= 128` before dispatching, and
// a longer id fell through to a 400. A wildcard bounds an id to one path segment
// but not to a length, so without carrying this over a 200-character id would
// reach the repository and come back 200 with an empty list. ⛔ It is deliberately
// looser than isRulePathID (64 characters for the custom form) because
// config-expanded ids like erc20-schedule_erc20-transfer-limit are long and
// legitimate — the branch's own comment said so, and the second row proves the
// looser bound is really the one in force.
func TestRuleRoutes_BudgetIdLengthGuardSurvivedTheMove(t *testing.T) {
	long := strings.Repeat("a", 200)
	within := strings.Repeat("a", 100)

	t.Run("over the cap is refused", func(t *testing.T) {
		fx := evm.NewRuleRouteFixture(t)
		rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodGet,
			"/api/v1/evm/rules/"+long+"/budgets", "", evm.RuleRouteAdminKey())
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Empty(t, fx.BudgetLists(), "⛔ the repository was never asked — the effect, not the status")
	})

	t.Run("a long but legal config-expanded id is not", func(t *testing.T) {
		fx := evm.NewRuleRouteFixture(t)
		rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodGet,
			"/api/v1/evm/rules/"+within+"/budgets", "", evm.RuleRouteAdminKey())
		assert.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
		assert.Equal(t, []string{within}, fx.BudgetLists())
	})

	t.Run("reset refuses it too", func(t *testing.T) {
		fx := evm.NewRuleRouteFixture(t)
		rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodPost,
			"/api/v1/evm/rules/"+long+"/budgets/reset", "", evm.RuleRouteAdminKey())
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Empty(t, fx.BudgetResets(), "⛔ nothing was reset")
	})
}

// TestRuleRoutes_ValidateIsALiteralOnlyForPost pins the one pattern overlap this
// module has, because Go's mux resolving it the right way is a property rather
// than an obvious fact.
//
// ⚠️ "validate" is a legal single segment, so POST /api/v1/evm/rules/validate and
// (from slice 3) POST /api/v1/evm/rules/{id} would both match that path; the
// literal segment is a strict subset of the wildcard, so the mux takes both and
// prefers the literal — proposal §2.2's safe shape, not the panicking one. ⭐ A
// GET on the same path is a rule lookup whose id happens to be "validate", which
// is exactly what ServeHTTP made of it (measured: 404 "rule not found"), and
// stays that way.
func TestRuleRoutes_ValidateIsALiteralOnlyForPost(t *testing.T) {
	fx := evm.NewRuleRouteFixture(t)
	patterns := rulePatterns(t, fx)
	assert.Contains(t, patterns, "POST /api/v1/evm/rules/validate")
	assert.NotContains(t, patterns, "GET /api/v1/evm/rules/validate",
		"⛔ nothing registers a GET here; the item route reads it as an id, which is what the prefix did")

	rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodPost,
		"/api/v1/evm/rules/validate", "", evm.RuleRouteAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
}

// TestRuleRoutes_NoVerbOrDepthReachesTheBudgetWrites is the negative space for
// the two budget endpoints, and ⭐ again the finding is a negative one: there was
// no verb hole. `GET /api/v1/evm/rules/{id}/budgets/reset` — the shape that on
// presets applied a preset and on signers unlocked a signer — was measured
// against the real registrations with a spy on ResetBudget and answered 400
// having called nothing, because the branch required POST and the fallthrough
// refused the reconstructed id.
func TestRuleRoutes_NoVerbOrDepthReachesTheBudgetWrites(t *testing.T) {
	id := evm.RuleRouteID

	for _, tc := range []struct{ name, method, path string }{
		{"GET on reset, which is the presets/signers shape", http.MethodGet, "/api/v1/evm/rules/" + id + "/budgets/reset"},
		{"DELETE on reset", http.MethodDelete, "/api/v1/evm/rules/" + id + "/budgets/reset"},
		{"PUT on reset", http.MethodPut, "/api/v1/evm/rules/" + id + "/budgets/reset"},
		{"reset one segment deep", http.MethodPost, "/api/v1/evm/rules/a/" + id + "/budgets/reset"},
		{"reset with a trailing slash", http.MethodPost, "/api/v1/evm/rules/" + id + "/budgets/reset/"},
		{"POST on budgets", http.MethodPost, "/api/v1/evm/rules/" + id + "/budgets"},
		{"DELETE on budgets", http.MethodDelete, "/api/v1/evm/rules/" + id + "/budgets"},
		{"budgets with a trailing slash", http.MethodGet, "/api/v1/evm/rules/" + id + "/budgets/"},
		{"budgets one segment deep", http.MethodGet, "/api/v1/evm/rules/a/" + id + "/budgets"},
		{"GET on batch validate", http.MethodGet, "/api/v1/evm/rules/validate/"},
		{"item validate one segment deep", http.MethodPost, "/api/v1/evm/rules/a/" + id + "/validate"},
		{"item validate with a trailing slash", http.MethodPost, "/api/v1/evm/rules/" + id + "/validate/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)

			rr := doRuleRouteRequest(t, ruleMux(t, fx), tc.method, tc.path, "", evm.RuleRouteAdminKey())
			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code,
				"%s %s reached a handler: %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
			assert.Empty(t, fx.BudgetResets(), "⛔ nothing was reset — the effect, not the status")
			assert.Empty(t, fx.BudgetLists(), "⛔ the budget repository was never read")
			assert.Equal(t, "pending_approval", fx.RuleStatus(id), "⛔ the rule is untouched")

			// ⭐ Control arm: the canonical reset does reach the handler and does run.
			ctl := evm.NewRuleRouteFixture(t)
			ctlRR := doRuleRouteRequest(t, ruleMux(t, ctl), http.MethodPost,
				"/api/v1/evm/rules/"+id+"/budgets/reset", "", evm.RuleRouteAdminKey())
			require.Equal(t, http.StatusOK, ctlRR.Code, "control arm body: %s", ctlRR.Body.String())
			require.Equal(t, []string{id}, ctl.BudgetLists(), "control arm must really read the budgets")
		})
	}
}

// ---------- proposal S8 slice 3: the collection, the item, and the prefix's death ----------

// TestRuleRoutes_TrailingSlashNoLongerMutates is the one defect this whole step
// closes, and the reason it is its own test rather than a row in the table below.
//
// ⛔ Measured before the change, against the two real registrations, by reading
// the repository back: "/api/v1/evm/rules/" matched every verb at every depth,
// ServeHTTP trimmed "/api/v1/evm/rules" and then trimmed the leading "/", and an
// empty remainder meant *the collection*. So `POST /api/v1/evm/rules/` answered
// 201 and **created a rule**. The item form did the same on the way out:
// "/api/v1/evm/rules/{id}/" trimmed to a clean id, so
// `DELETE /api/v1/evm/rules/{id}/` answered 204 and **deleted the row**.
//
// ⚠️ This is proposal lesson 3's "trailing slash cuts both ways", in the direction
// that mutates — the same shape as `DELETE /signers/{addr}/` and
// `POST /templates/`. Go's mux never strips a trailing slash, so {id} does not
// match the empty segment and the collection pattern does not match a path with
// one: every shape below reaches no pattern.
//
// ⭐ The assertion is the effect, not the status.
func TestRuleRoutes_TrailingSlashNoLongerMutates(t *testing.T) {
	id := evm.RuleRouteID
	const createBody = `{"name":"probe","type":"evm_address_list","mode":"whitelist",` +
		`"config":{"addresses":["0x0000000000000000000000000000000000000009"]}}`

	t.Run("POST on the collection with a trailing slash, which created a rule", func(t *testing.T) {
		fx := evm.NewRuleRouteFixture(t)
		rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodPost, "/api/v1/evm/rules/",
			createBody, evm.RuleRouteAdminKey())
		assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code,
			"body: %s", rr.Body.String())
		assert.Equal(t, []string{id}, fx.RuleIDs(),
			"⛔ this used to answer 201 and write a second row")

		// ⭐ Control arm: without the slash it really does create.
		ctl := evm.NewRuleRouteFixture(t)
		ctlRR := doRuleRouteRequest(t, ruleMux(t, ctl), http.MethodPost, "/api/v1/evm/rules",
			createBody, evm.RuleRouteAdminKey())
		require.Equal(t, http.StatusCreated, ctlRR.Code, "control arm body: %s", ctlRR.Body.String())
		require.Len(t, ctl.RuleIDs(), 2, "control arm must really create")
	})

	t.Run("DELETE on an item with a trailing slash, which deleted it", func(t *testing.T) {
		fx := evm.NewRuleRouteFixture(t)
		rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodDelete, "/api/v1/evm/rules/"+id+"/",
			"", evm.RuleRouteAdminKey())
		assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code,
			"body: %s", rr.Body.String())
		assert.Equal(t, []string{id}, fx.RuleIDs(), "⛔ this used to answer 204 and remove the row")

		// ⭐ Control arm: without the slash it really does delete.
		ctl := evm.NewRuleRouteFixture(t)
		ctlRR := doRuleRouteRequest(t, ruleMux(t, ctl), http.MethodDelete, "/api/v1/evm/rules/"+id,
			"", evm.RuleRouteAdminKey())
		require.Equal(t, http.StatusNoContent, ctlRR.Code, "control arm body: %s", ctlRR.Body.String())
		require.Empty(t, ctl.RuleIDs(), "control arm must really delete")
	})
}

// TestRuleRoutes_UnclaimedShapesReachNoEndpoint replaces the guard tests the
// decomposition removed — TestRuleHandler_MethodNotAllowed above all, which
// asserted that ServeHTTP's own method switch answered 405 for
// `PUT /api/v1/evm/rules`.
//
// ⭐ Strictly stronger than what it replaces: that test asserted a status from a
// handler's own guard. The guard is gone because no pattern routes those verbs or
// shapes anywhere, so this drives the production pattern set, asserts the mux
// resolved *no* route, and asserts nothing ran — which a status-only check would
// not catch in a handler that mutated first and refused afterwards.
//
// ⚠️ A daemon answers differently and better: "/api/v1/" matches every path and
// every method, so every row here lands on the JSON 404 fallback rather than on
// this bare mux's 404/405. That is api.TestAPIFallback_RulesStrandedPaths' subject.
func TestRuleRoutes_UnclaimedShapesReachNoEndpoint(t *testing.T) {
	id := evm.RuleRouteID

	for _, tc := range []struct{ name, method, path string }{
		// ---- verbs no route declares (the removed guard tests) ----
		{"PUT on the collection, which was TestRuleHandler_MethodNotAllowed", http.MethodPut, "/api/v1/evm/rules"},
		{"DELETE on the collection", http.MethodDelete, "/api/v1/evm/rules"},
		{"PATCH on the collection", http.MethodPatch, "/api/v1/evm/rules"},
		{"PUT on an item", http.MethodPut, "/api/v1/evm/rules/" + id},
		{"POST on an item", http.MethodPost, "/api/v1/evm/rules/" + id},

		// ---- trailing slash on the reads, which the prefix forgave ----
		{"the collection with a trailing slash, which listed", http.MethodGet, "/api/v1/evm/rules/"},
		{"an item with a trailing slash, which read the rule", http.MethodGet, "/api/v1/evm/rules/" + id + "/"},

		// ---- extra depth, which answered rule.go's own 400 ----
		{"a deep path", http.MethodGet, "/api/v1/evm/rules/a/b/c/d"},
		{"two segments", http.MethodGet, "/api/v1/evm/rules/a/b"},
		{"an unknown sub-action", http.MethodGet, "/api/v1/evm/rules/" + id + "/unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)

			rr := doRuleRouteRequest(t, ruleMux(t, fx), tc.method, tc.path,
				`{"name":"x","type":"evm_address_list","mode":"whitelist"}`, evm.RuleRouteAdminKey())

			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code,
				"%s %s reached a handler: %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
			assert.Equal(t, []string{id}, fx.RuleIDs(), "⛔ no row created or deleted")
			assert.Equal(t, "pending_approval", fx.RuleStatus(id), "⛔ the rule is untouched")
			assert.Empty(t, fx.BudgetResets(), "⛔ nothing was reset")
		})
	}
}

// TestRuleRoutes_ItemIdGuardsSurvivedTheMove pins the two item-route guards that
// the {id} wildcard does not reproduce, because they are the two most likely to
// be dropped: they lived in the bottom switch of ServeHTTP rather than in the
// endpoint functions.
//
// ⚠️ isRulePathID is what makes a malformed id a 400 rather than a 404 — the item
// switch ran it, the sub-action branches did not, and several handler tests say
// so. The synthetic-id refusal is the PATCH arm's own: a `sim:0x…` placeholder
// row exists only to satisfy the budget table's foreign key and is readable and
// deletable but not modifiable.
func TestRuleRoutes_ItemIdGuardsSurvivedTheMove(t *testing.T) {
	const synthetic = "sim:0x1111111111111111111111111111111111111111"

	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"a malformed id on GET", http.MethodGet, "/api/v1/evm/rules/not$valid", "", http.StatusBadRequest},
		{"a malformed id on PATCH", http.MethodPatch, "/api/v1/evm/rules/not$valid", `{"enabled":false}`, http.StatusBadRequest},
		{"a malformed id on DELETE", http.MethodDelete, "/api/v1/evm/rules/not$valid", "", http.StatusBadRequest},
		{"a 200-character id on GET", http.MethodGet, "/api/v1/evm/rules/" + strings.Repeat("a", 200), "", http.StatusBadRequest},
		{"a synthetic simulation id is not PATCHable", http.MethodPatch, "/api/v1/evm/rules/" + synthetic, `{"enabled":false}`, http.StatusForbidden},
		// ⚠️ …but it is readable, which is what makes the row above a rule about
		// PATCH rather than about the id shape. 404 because the fixture holds no
		// such row; what matters is that it got past the guard to the repository.
		{"a synthetic simulation id is readable", http.MethodGet, "/api/v1/evm/rules/" + synthetic, "", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)
			rr := doRuleRouteRequest(t, ruleMux(t, fx), tc.method, tc.path, tc.body, evm.RuleRouteAdminKey())
			assert.Equal(t, tc.want, rr.Code, "body: %s", rr.Body.String())
			assert.Equal(t, []string{evm.RuleRouteID}, fx.RuleIDs(), "⛔ no row created or deleted")
		})
	}
}

// TestRuleRoutes_HeadOnTheReadsIsAWidening pins the two answers that got *more*
// permissive, so that they are a recorded decision rather than a surprise.
//
// ⚠️ Go's mux matches HEAD against a GET pattern and net/http drops the body, so
// HEAD now reaches ListRules and GetRule where ServeHTTP's method switch answered
// 405 (the collection pattern carried no method at all). Both are pure reads. The
// same widening happened to settings in S5 and to templates, presets and requests
// in S6/S7; it is listed in module_rules.go's table.
func TestRuleRoutes_HeadOnTheReadsIsAWidening(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"the collection", "/api/v1/evm/rules"},
		{"one rule", "/api/v1/evm/rules/" + evm.RuleRouteID},
		{"one rule's budgets", "/api/v1/evm/rules/" + evm.RuleRouteID + "/budgets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := evm.NewRuleRouteFixture(t)
			rr := doRuleRouteRequest(t, ruleMux(t, fx), http.MethodHead, tc.path, "", evm.RuleRouteAdminKey())
			assert.Equal(t, http.StatusOK, rr.Code,
				"HEAD now reaches the read endpoint; it used to be the handler's own 405")
		})
	}
}
