// Package handler_test — this file holds the template *instance* route tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S6)
//
// S6 deletes TemplateHandler.ServeInstanceHTTP and the closure in setupRoutes
// that fed it, replacing both with one route pattern and
// TemplateHandler.RevokeInstance reading r.PathValue. The questions below are
// about which request reaches that function, and after the change that is
// decided by internal/api's route registration — so answering them means going
// through it.
//
// ⛔ The tempting way — build an http.ServeMux in the fixture and register
// "/api/v1/templates/instances/{ruleID}/revoke" by hand — creates a second
// source of truth for the route table. It drifts from the production
// registration silently: the tests stay green while exercising a route the
// daemon does not serve. So the pattern comes from api.templatesModule's
// Routes(), reached through the exported api.Module / api.RouteRegistrar pair,
// and it is written down here only in the one test whose subject *is* the
// pattern list.
//
// ⚠️ Which is why this is `package handler_test`: internal/api imports
// internal/api/handler, so an in-package test file cannot import internal/api
// back — that is an import cycle. The cost is that these tests can only use
// exported identifiers, which is what TemplateInstanceFixture in template_test.go
// exists for.
//
// ⚠️ What these tests do NOT exercise: the middleware chain. The route
// registers as Permitted(PermReadTemplates), whose chain begins with
// AuthMiddleware, which refuses any request lacking X-API-Key-ID / X-Timestamp
// / X-Signature. These tests inject an API key through the request context
// instead, as the template family always has. So the test registrar drops the
// RouteAuth it is handed and registers the bare handler: what is under test is
// dispatch. ⛔ Do not read a green run here as evidence that the route is
// correctly permissioned — it is a mutating route on a read permission, which
// module_templates.go records in writing and
// scripts/lib/arch-baseline/ast/route-mutating-perm.txt ratchets.
//
// ⚠️ The mux these tests build holds only the module's own route — no
// "/api/v1/templates/" prefix and no /api/v1/ fallback — so an unclaimed path
// gets the mux's own 404. ⛔ A daemon answers differently and worse: the
// templates prefix is still registered (see module_templates.go for why), so
// these paths reach TemplateHandler.ServeHTTP and come back "template not
// found". That difference is measured, not assumed, and stated in
// module_templates.go's table.
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

// templateInstanceMux registers the production template-instance route over an
// otherwise empty mux.
//
// ⭐ An empty mux is deliberate: a path the pattern does not claim must reach
// nothing at all, which is exactly the property the "/api/v1/templates/"
// closure could not have.
func templateInstanceMux(t *testing.T, h *handler.TemplateHandler) http.Handler {
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

// TestTemplateInstanceRoutes_RegistersExactlyTheProductionPatterns is the
// assertion that keeps a decomposition from quietly changing authorization.
//
// ⛔ It asserts the pattern *and* its RouteAuth. The permission is copied
// verbatim from the "/api/v1/templates/" prefix this route came out of, and
// this test plus route-perm-binding are the only two things that would notice a
// change. Negatively verified: swapping PermReadTemplates for another
// permission reddens both.
func TestTemplateInstanceRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
	mod, err := api.NewTemplatesModule(fx.Handler)
	require.NoError(t, err)

	got := map[string]string{}
	mod.Routes(templateRecordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got[pattern] = auth.String()
	}})

	assert.Equal(t, map[string]string{
		"POST /api/v1/templates/instances/{ruleID}/revoke": "permitted(read_templates)",
	}, got, "⛔ the templates module registers exactly one route, with the permission the prefix it "+
		"replaced declared; changing either is a security decision, not a refactor (proposal §2.5)")
	assert.Equal(t, "templates", mod.Name())
}

// TestTemplateInstanceRoutes_RevokePost is the positive control for every
// refusal test below: the same fixture, driven the way a client drives it,
// revokes the instance. Without it a green refusal test could mean the fixture
// was incapable.
//
// ⭐ It also pins the PathValue plumbing: the response echoes rule_id, so an
// id read from the wrong place shows up as a wrong echo rather than as a
// generic 404.
func TestTemplateInstanceRoutes_RevokePost(t *testing.T) {
	fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
	mux := templateInstanceMux(t, fx.Handler)

	rr := doTemplateRouteRequest(t, mux, http.MethodPost, "/api/v1/templates/instances/"+routeRuleID+"/revoke", "")
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "revoked", resp["status"])
	assert.Equal(t, routeRuleID, resp["rule_id"], "the id must come from {ruleID}")
	assert.True(t, fx.Revoked(t, routeRuleID), "the instance really is switched off")
}

// TestTemplateInstanceRoutes_RevokeRequiresPost replaces
// TestRevokeInstance/method_not_allowed_on_revoke and
// TestCoverage_Template_ServeInstanceHTTP_MethodNotAllowed, which asserted that
// ServeInstanceHTTP wrote 405 for a non-POST.
//
// ⭐ Strictly stronger than what it replaces: the guard is gone from the
// handler because no pattern routes those verbs anywhere, so this drives the
// production pattern set, asserts the mux resolved *no* pattern, and asserts
// the instance was not revoked — which a status-only check would not catch in a
// handler that mutated first and refused afterwards.
func TestTemplateInstanceRoutes_RevokeRequiresPost(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPatch, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
			mux := templateInstanceMux(t, fx.Handler)
			path := "/api/v1/templates/instances/" + routeRuleID + "/revoke"

			rr := doTemplateRouteRequest(t, mux, method, path, "")
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code,
				"the bare mux answers 405 because a sibling method is registered on this path; "+
					"a daemon answers the templates prefix's 404 instead — see module_templates.go")
			assert.False(t, fx.Revoked(t, routeRuleID),
				"⛔ %s must not revoke — and this is the assertion that matters, not the status", method)
		})
	}
}

// TestTemplateInstanceRoutes_UnclaimedPathDoesNotRevoke replaces
// TestRevokeInstance/invalid_path_returns_404 and
// TestCoverage_Template_ServeInstanceHTTP_NotFound.
//
// ⚠️ Row 3 is the one that was a real defect: TrimPrefix + TrimSuffix accepted
// any depth, so POST /api/v1/templates/instances/a/b/revoke reached the service
// with ruleID "a/b" — the same swallow S4 found on the signer access sub-tree.
// {ruleID} is exactly one segment, so it is unrepresentable now.
func TestTemplateInstanceRoutes_UnclaimedPathDoesNotRevoke(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"no revoke suffix", "/api/v1/templates/instances/" + routeRuleID},
		{"unknown suffix", "/api/v1/templates/instances/" + routeRuleID + "/unknown"},
		{"deeper than the endpoint", "/api/v1/templates/instances/a/b/revoke"},
		{"trailing slash", "/api/v1/templates/instances/" + routeRuleID + "/revoke/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := handler.NewTemplateInstanceFixture(t, routeRuleID)
			mux := templateInstanceMux(t, fx.Handler)

			rr := doTemplateRouteRequest(t, mux, http.MethodPost, tc.path, "")
			assert.Equal(t, http.StatusNotFound, rr.Code, "no template route claims %s", tc.path)
			assert.False(t, fx.Revoked(t, routeRuleID), "nothing was revoked")

			// ⭐ Control arm: the handler itself would have answered. Without it a
			// green run above could mean the fixture was broken rather than that
			// routing refused the path.
			direct := httptest.NewRequest(http.MethodPost, tc.path, nil)
			direct.SetPathValue("ruleID", routeRuleID)
			direct = direct.WithContext(context.WithValue(direct.Context(),
				middleware.APIKeyContextKey, handler.TemplateRouteAdminKey()))
			rec := httptest.NewRecorder()
			fx.Handler.RevokeInstance(rec, direct)
			require.Equal(t, http.StatusOK, rec.Code, "control arm: a direct call does revoke")
			assert.True(t, fx.Revoked(t, routeRuleID))
		})
	}
}
