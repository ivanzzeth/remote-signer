// Package handler_test — this file holds the template route tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S6)
//
// S6 deleted TemplateHandler.ServeHTTP and TemplateHandler.ServeInstanceHTTP
// along with the two method-less prefixes and the closure in setupRoutes that
// fed them, replacing all of it with eight route patterns and endpoint functions
// that read r.PathValue. The questions below are about which request reaches
// which function, and after the change that is decided by internal/api's route
// registration — so answering them means going through it.
//
// ⛔ The tempting way — build an http.ServeMux in the fixture and register
// "/api/v1/templates/{id}" and friends by hand — creates a second source of
// truth for the route table. It drifts from the production registration
// silently: the tests stay green while exercising routes the daemon does not
// serve. So the patterns come from api.templatesModule's Routes(), reached
// through the exported api.Module / api.RouteRegistrar pair, and they are
// written down here only in the one test whose subject *is* the pattern list.
//
// ⚠️ Which is why this is `package handler_test`: internal/api imports
// internal/api/handler, so an in-package test file cannot import internal/api
// back — that is an import cycle. The cost is that these tests can only use
// exported identifiers, which is what TemplateInstanceFixture in template_test.go
// exists for.
//
// ⚠️ What these tests do NOT exercise: the middleware chain. Every route
// registers as Permitted(PermReadTemplates), whose chain begins with
// AuthMiddleware, which refuses any request lacking X-API-Key-ID / X-Timestamp /
// X-Signature. These tests inject an API key through the request context
// instead, as the template family always has. So the test registrar drops the
// RouteAuth it is handed and registers the bare handler: what is under test is
// dispatch. ⛔ Do not read a green run here as evidence that these routes are
// correctly permissioned — four of them are mutating routes on a read
// permission, which module_templates.go records in writing and
// scripts/lib/arch-baseline/ast/route-mutating-perm.txt ratchets.
//
// ⚠️ The mux these tests build holds only the module's own routes — no
// "/api/v1/templates/" prefix (there is none any more) and no /api/v1/ fallback
// — so an unclaimed path gets the mux's own 404 or 405. ⛔ A daemon answers
// differently: "/api/v1/" matches every path and every method, so every stranded
// shape lands on the JSON 404 fallback instead. That difference is measured, not
// assumed, in api.TestAPIFallback_TemplateStrandedPaths.
package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// ---------- the registrar ----------
//
// ⚠️ Named template* rather than reusing the wallet, api-key or settings
// families' registrars: those live in this same external package (two of them
// behind `//go:build integration`), so a shared name would be a redeclaration
// under that tag. Same shape, different name.

type templateMuxRegistrar struct{ mux *http.ServeMux }

func (m templateMuxRegistrar) Handle(pattern string, _ api.RouteAuth, h http.Handler) {
	m.mux.Handle(pattern, h)
}

type templateRecordingRegistrar struct {
	record func(pattern string, auth api.RouteAuth)
}

func (r templateRecordingRegistrar) Handle(pattern string, auth api.RouteAuth, _ http.Handler) {
	r.record(pattern, auth)
}

const routeRuleID = "inst_9f3a2b1c4d5e6f70"

// encodedSlashedID is what every client now puts on the wire for a registry
// template id. ⭐ Written with url.PathEscape rather than as the literal
// "evm%2Ferc20" so that the test says *why* the string looks like that.
var encodedSlashedID = url.PathEscape(handler.SlashedTemplateID)

// templateMux registers the production template routes over an otherwise empty
// mux.
//
// ⭐ An empty mux is deliberate: a path the patterns do not claim must reach
// nothing at all, which is exactly the property the two "/api/v1/templates"
// prefixes could not have.
func templateMux(t *testing.T, h *handler.TemplateHandler) http.Handler {
	t.Helper()
	mod, err := api.NewTemplatesModule(h)
	require.NoError(t, err)
	require.NotNil(t, mod, "no module means no pattern would be registered, and every request below "+
		"would 404 for a reason that has nothing to do with what is under test")

	mux := http.NewServeMux()
	mod.Routes(templateMuxRegistrar{mux: mux})
	return mux
}

func doTemplateRouteRequest(t *testing.T, mux http.Handler, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, handler.TemplateRouteAdminKey()))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestTemplateRoutes_RegistersExactlyTheProductionPatterns is the assertion that
// keeps a decomposition from quietly changing authorization.
//
// ⛔ It asserts every pattern *and* its RouteAuth. The permission is copied
// verbatim from the two prefixes these routes came out of, and this test plus
// route-perm-binding are the only two things that would notice a change.
// Negatively verified: swapping PermReadTemplates for another permission on any
// one route reddens both.
//
// ⚠️ Read the four mutating rows deliberately. create, update, delete and
// instantiate carry a *read* permission, and that is not a mistake introduced
// here — it is what the method-less prefix declared for all seven endpoints
// behind it, and a method-less prefix is precisely what route-mutating-perm
// cannot see. ⛔ Tightening them is a security decision and its own PR.
func TestTemplateRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
	mod, err := api.NewTemplatesModule(fx.Handler)
	require.NoError(t, err)

	got := map[string]string{}
	mod.Routes(templateRecordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got[pattern] = auth.String()
	}})

	assert.Equal(t, map[string]string{
		"GET /api/v1/templates":                            "permitted(read_templates)",
		"POST /api/v1/templates":                           "permitted(read_templates)",
		"GET /api/v1/templates/{id}":                       "permitted(read_templates)",
		"PATCH /api/v1/templates/{id}":                     "permitted(read_templates)",
		"DELETE /api/v1/templates/{id}":                    "permitted(read_templates)",
		"POST /api/v1/templates/{id}/instantiate":          "permitted(read_templates)",
		"POST /api/v1/templates/{id}/validate":             "permitted(read_templates)",
		"POST /api/v1/templates/instances/{ruleID}/revoke": "permitted(read_templates)",
	}, got, "⛔ the templates module registers exactly these eight routes, each with the permission the "+
		"prefix it replaced declared; changing either is a security decision, not a refactor (proposal §2.5)")
	assert.Equal(t, "templates", mod.Name())
}

// TestTemplateRoutes_EncodedSlashedIDReachesTheEndpoint is the test the whole of
// S6's second half was blocked on, and it is the positive control for every
// refusal below.
//
// ⭐ What it pins is the round trip proposal §2.3 row 2 predicted and got
// backwards: Go's ServeMux splits the *escaped* path on literal '/' and
// unescapes each segment afterwards, so "evm%2Ferc20" stays one segment and
// PathValue("id") hands the handler "evm/erc20" with no PathUnescape anywhere in
// the handler. The response echoes the id, so an id read from the wrong place
// shows up as a wrong echo rather than as a generic 404.
func TestTemplateRoutes_EncodedSlashedIDReachesTheEndpoint(t *testing.T) {
	fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
	mux := templateMux(t, fx.Handler)

	rr := doTemplateRouteRequest(t, mux, http.MethodGet, "/api/v1/templates/"+encodedSlashedID, "")
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, handler.SlashedTemplateID, resp["id"],
		"the id must come from {id}, decoded by the mux — %q went out on the wire", encodedSlashedID)
}

// TestTemplateRoutes_EveryEndpointIsReachable walks the production pattern list
// and drives each route once, so that a route registered but wired to the wrong
// function, or a {id} a handler reads under another name, fails by name.
//
// ⛔ The pattern list is not written here — it comes from Routes(). A literal
// list would be the second route table this file exists to avoid.
func TestTemplateRoutes_EveryEndpointIsReachable(t *testing.T) {
	fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
	mod, err := api.NewTemplatesModule(fx.Handler)
	require.NoError(t, err)

	var patterns []string
	mod.Routes(templateRecordingRegistrar{record: func(pattern string, _ api.RouteAuth) {
		patterns = append(patterns, pattern)
	}})
	require.Len(t, patterns, 8, "the rows below would pass for the wrong reason if the module registered "+
		"a different number of routes")

	// A body good enough that no endpoint stops at "invalid request body"; each
	// endpoint may still refuse for its own reasons, which is why the assertion
	// below is about *not* being unrouted rather than about a status.
	const body = `{"name":"probe","type":"evm_address_list","mode":"whitelist","config":{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]},"enabled":true,"variables":{}}`

	for _, pattern := range patterns {
		method, path, ok := strings.Cut(pattern, " ")
		require.True(t, ok, "pattern %q has no method — every template route is method-scoped", pattern)

		target := strings.NewReplacer("{id}", encodedSlashedID, "{ruleID}", routeRuleID).Replace(path)
		require.NotContains(t, target, "{", "pattern %q has a wildcard this test does not know how to fill", pattern)

		t.Run(pattern, func(t *testing.T) {
			fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
			mux := templateMux(t, fx.Handler)

			rr := doTemplateRouteRequest(t, mux, method, target, body)
			// ⭐ 404 and 405 are the two answers a bare mux gives when nothing
			// matched. Any other status means a handler ran, which is all this
			// row claims — each endpoint's own behaviour is the subject of the
			// handler-package tests.
			assert.NotEqual(t, http.StatusNotFound, rr.Code,
				"%s reached no handler: body %s", pattern, rr.Body.String())
			assert.NotEqual(t, http.StatusMethodNotAllowed, rr.Code,
				"%s reached no handler: body %s", pattern, rr.Body.String())
		})
	}
}

// TestTemplateRoutes_RawSlashIDNoLongerMatches is the behaviour this step
// deliberately withdraws, asserted rather than left to be discovered.
//
// ⛔ Before the decomposition all three of these answered *successfully*:
// "/api/v1/templates/evm/erc20" reached getTemplate with id "evm/erc20" because
// ServeHTTP took the whole remainder as an id, and the two sub-action rows
// reached instantiate and validate through its TrimSuffix ladder. That is the
// ambiguity the route table cannot express — the same path is equally "template
// evm, sub-action erc20" — and it is why every client had to start
// percent-encoding before this commit could exist.
//
// ⚠️ This is the one place in the file where an unmatched path is the *desired*
// answer for a path a client might really have sent. Every in-repo client sends
// the encoded form now (pkg/client, pkg/rs-client, pkg/js-client, the extension
// bundle, cmd/smoke-test, both e2e call sites); a published npm
// remote-signer-client 0.0.5 does not, and module_templates.go says so.
func TestTemplateRoutes_RawSlashIDNoLongerMatches(t *testing.T) {
	for _, tc := range []struct{ name, method, path string }{
		{"get, which returned the template", http.MethodGet, "/api/v1/templates/evm/erc20"},
		{"instantiate, which ran", http.MethodPost, "/api/v1/templates/evm/erc20/instantiate"},
		{"validate, which ran", http.MethodPost, "/api/v1/templates/evm/erc20/validate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
			mux := templateMux(t, fx.Handler)
			before := fx.TemplateCount(t)

			rr := doTemplateRouteRequest(t, mux, tc.method, tc.path, `{"variables":{}}`)
			assert.Equal(t, http.StatusNotFound, rr.Code,
				"no template route claims %s %s — the raw '/' makes it ambiguous", tc.method, tc.path)
			assert.True(t, fx.TemplateExists(t, handler.SlashedTemplateID),
				"the template itself is untouched")
			assert.Equal(t, before, fx.TemplateCount(t), "nothing was created")

			// ⭐ Control arm: the same request against the encoded id does reach a
			// handler. Without it a green run above could mean the fixture was
			// incapable rather than that routing refused the raw form.
			encoded := strings.Replace(tc.path, handler.SlashedTemplateID, encodedSlashedID, 1)
			ctl := doTemplateRouteRequest(t, mux, tc.method, encoded, `{"variables":{}}`)
			require.NotEqual(t, http.StatusNotFound, ctl.Code,
				"control arm: %s %s must reach a handler, body %s", tc.method, encoded, ctl.Body.String())
		})
	}
}

// TestTemplateRoutes_UnclaimedShapesReachNoEndpoint replaces the five 405 tests
// the decomposition removed — TestListTemplates/method_not_allowed,
// TestGetTemplate/method_not_allowed_on_single_template,
// TestInstantiateTemplate/method_not_allowed_on_instantiate,
// TestInstantiateTemplate_MethodNotAllowedOnInstantiate and
// TestCoverage_ValidateTemplate_MethodNotAllowed — plus the depth and
// trailing-slash shapes nothing ever asserted.
//
// ⭐ Strictly stronger than what it replaces: those five asserted a status from
// ServeHTTP's own method guards. Those guards are gone because no pattern routes
// those verbs anywhere, so this drives the production pattern set, asserts the
// mux resolved *no* route, and asserts the repository did not move — which a
// status-only check would not catch in a handler that mutated first and refused
// afterwards.
//
// ⛔ And read the verb rows for what they are. On presets, signers and
// hd-wallets the equivalent rows were live defects (a GET that applied a preset,
// unlocked a signer, ran a derivation). On templates they were not: ServeHTTP
// checked the method in all three of its branches, so each of these answered 405
// and mutated nothing. What changes is that the guard is now unrepresentable
// rather than merely written down.
func TestTemplateRoutes_UnclaimedShapesReachNoEndpoint(t *testing.T) {
	id := encodedSlashedID

	for _, tc := range []struct{ name, method, path string }{
		// ---- verbs no route declares (the five removed 405 tests) ----
		{"PUT on the collection", http.MethodPut, "/api/v1/templates"},
		{"POST on an item", http.MethodPost, "/api/v1/templates/" + id},
		{"PUT on an item", http.MethodPut, "/api/v1/templates/" + id},
		{"GET on instantiate", http.MethodGet, "/api/v1/templates/" + id + "/instantiate"},
		{"PUT on instantiate", http.MethodPut, "/api/v1/templates/" + id + "/instantiate"},
		{"GET on validate", http.MethodGet, "/api/v1/templates/" + id + "/validate"},
		{"DELETE on validate", http.MethodDelete, "/api/v1/templates/" + id + "/validate"},
		{"GET on revoke", http.MethodGet, "/api/v1/templates/instances/" + routeRuleID + "/revoke"},

		// ---- trailing slash, which ServeHTTP forgave on the collection ----
		// ⚠️ Both directions of the S4 lesson are here. "/api/v1/templates/" was
		// *forgiven*: TrimPrefix("/api/v1/templates") then TrimPrefix("/") left the
		// empty string, so it was the collection — a GET listed and a POST created.
		// The deeper ones were already refused, because the ladder never trimmed a
		// trailing slash and the id simply came out with one on the end.
		{"the collection with a trailing slash, which listed", http.MethodGet, "/api/v1/templates/"},
		{"the collection with a trailing slash, which created", http.MethodPost, "/api/v1/templates/"},
		{"an item with a trailing slash", http.MethodGet, "/api/v1/templates/" + id + "/"},
		{"instantiate with a trailing slash", http.MethodPost, "/api/v1/templates/" + id + "/instantiate/"},
		{"validate with a trailing slash", http.MethodPost, "/api/v1/templates/" + id + "/validate/"},
		{"revoke with a trailing slash", http.MethodPost, "/api/v1/templates/instances/" + routeRuleID + "/revoke/"},

		// ---- extra depth, which the suffix ladder swallowed ----
		// ⚠️ The instantiate row is the one that was a real defect: TrimPrefix plus
		// TrimSuffix accepted any depth, so this reached instantiateTemplate with
		// templateID "a/b/c". {id} is exactly one segment, so it cannot happen.
		{"instantiate three segments deep, which ran on \"a/b/c\"", http.MethodPost, "/api/v1/templates/a/b/c/instantiate"},
		{"a deep path", http.MethodGet, "/api/v1/templates/a/b/c/d"},
		{"an unknown sub-action", http.MethodGet, "/api/v1/templates/" + id + "/unknown"},
		{"revoke two segments deep, which revoked \"a/b\"", http.MethodPost, "/api/v1/templates/instances/a/b/revoke"},
		{"an instance with no revoke suffix", http.MethodPost, "/api/v1/templates/instances/" + routeRuleID},
		{"an instance with an unknown sub-action", http.MethodPost, "/api/v1/templates/instances/" + routeRuleID + "/unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
			mux := templateMux(t, fx.Handler)
			before := fx.TemplateCount(t)

			rr := doTemplateRouteRequest(t, mux, tc.method, tc.path, `{"name":"x","type":"evm_address_list","mode":"whitelist","config":{},"enabled":true}`)

			// ⚠️ 404 or 405: a bare mux answers 405 when a sibling method is
			// registered on the very same path and 404 otherwise. ⛔ Which one it
			// is says nothing a client can rely on — a daemon answers the
			// /api/v1/ fallback's 404 for every row here, which is
			// api.TestAPIFallback_TemplateStrandedPaths' subject. What matters is
			// that no endpoint ran.
			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code,
				"%s %s reached a handler: %d %s", tc.method, tc.path, rr.Code, rr.Body.String())

			assert.Equal(t, before, fx.TemplateCount(t), "⛔ nothing was created or deleted")
			assert.True(t, fx.TemplateExists(t, handler.SlashedTemplateID), "the template is still there")
			assert.Equal(t, "ERC20 under route test", fx.TemplateName(t, handler.SlashedTemplateID),
				"⛔ nothing was updated — and this is the assertion that matters, not the status")
			assert.False(t, fx.Revoked(t, routeRuleID), "⛔ nothing was revoked")
		})
	}
}

// TestTemplateRoutes_RevokePost is the instance sub-tree's positive control: the
// same fixture, driven the way a client drives it, revokes the instance.
//
// ⭐ It also pins the PathValue plumbing: the response echoes rule_id, so an id
// read from the wrong place shows up as a wrong echo rather than as a generic
// 404.
func TestTemplateRoutes_RevokePost(t *testing.T) {
	fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
	mux := templateMux(t, fx.Handler)

	rr := doTemplateRouteRequest(t, mux, http.MethodPost, "/api/v1/templates/instances/"+routeRuleID+"/revoke", "")
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "revoked", resp["status"])
	assert.Equal(t, routeRuleID, resp["rule_id"], "the id must come from {ruleID}")
	assert.True(t, fx.Revoked(t, routeRuleID), "the instance really is switched off")
}

// TestTemplateRoutes_RevokeRequiresPost replaces
// TestRevokeInstance/method_not_allowed_on_revoke and
// TestCoverage_Template_ServeInstanceHTTP_MethodNotAllowed, which asserted that
// ServeInstanceHTTP wrote 405 for a non-POST.
//
// ⭐ Strictly stronger than what it replaces: the guard is gone from the handler
// because no pattern routes those verbs anywhere, so this drives the production
// pattern set, asserts the mux resolved *no* pattern, and asserts the instance
// was not revoked.
func TestTemplateRoutes_RevokeRequiresPost(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPatch, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
			mux := templateMux(t, fx.Handler)
			path := "/api/v1/templates/instances/" + routeRuleID + "/revoke"

			rr := doTemplateRouteRequest(t, mux, method, path, "")
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code,
				"the bare mux answers 405 because a sibling method is registered on this path; "+
					"a daemon answers the /api/v1/ fallback's 404 instead — see module_templates.go")
			assert.False(t, fx.Revoked(t, routeRuleID),
				"⛔ %s must not revoke — and this is the assertion that matters, not the status", method)
		})
	}
}

// TestTemplateRoutes_HeadOnTheCollectionIsAWidening pins the one answer that got
// *more* permissive, so that it is a recorded decision rather than a surprise.
//
// ⚠️ Go's mux matches HEAD against a GET pattern and net/http drops the body, so
// HEAD on the collection reaches ListTemplates where ServeHTTP's `switch
// r.Method` default used to answer 405. The endpoint is a pure read. The same
// widening happened to settings in S5 and to presets in S6's first half; it is
// listed in module_templates.go's table.
func TestTemplateRoutes_HeadOnTheCollectionIsAWidening(t *testing.T) {
	fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
	mux := templateMux(t, fx.Handler)

	rr := doTemplateRouteRequest(t, mux, http.MethodHead, "/api/v1/templates", "")
	assert.Equal(t, http.StatusOK, rr.Code,
		"HEAD now reaches ListTemplates; it used to be ServeHTTP's 405")
}
