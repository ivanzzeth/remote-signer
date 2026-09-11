package api

import (
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// templatesModule serves the whole template surface: the catalogue, one
// template, its two sub-actions, and revoking an instance minted from it.
//
// # Why it is a module (proposal S6, copying S3–S5's shape)
//
// A module is what lets a test drive the *production* route patterns. Routes()
// is exported and RouteRegistrar is an interface, so internal/api/handler's
// external test package (package handler_test — an in-package test cannot
// import internal/api, which imports the handler package) can hand in a
// registrar of its own and get these patterns into a bare http.ServeMux. A mux
// built in a fixture with the patterns typed in by hand is a second source of
// truth that stays green while describing routes the daemon does not serve.
//
// ⚠️ Like the signers, settings and presets modules it is handed an
// already-constructed handler: NewTemplateHandler takes four arguments and four
// options read off Router state (two live setting predicates, the API-key repo,
// the JS evaluator, the Solidity validator). Moving that wiring here would move
// Router internals with it and has no bearing on the route table.
type templatesModule struct {
	h *handler.TemplateHandler
}

// NewTemplatesModule wraps a constructed template handler. It errors rather
// than registering routes that would nil-panic on the first request.
func NewTemplatesModule(h *handler.TemplateHandler) (Module, error) {
	if h == nil {
		return nil, fmt.Errorf("template handler is required")
	}
	return &templatesModule{h: h}, nil
}

func (m *templatesModule) Name() string { return "templates" }

// Routes registers the template surface: eight endpoints, named (proposal S6).
//
// # What changed and what did not
//
// This used to be three patterns. One of them — the instances revoke — was
// named in an earlier step; the other two were method-less prefixes serving
// seven endpoints between them:
//
//	/api/v1/templates      (any method)                  (PermReadTemplates)
//	/api/v1/templates/     (any method, any depth)       (PermReadTemplates)
//
// TemplateHandler.ServeHTTP then cut r.URL.EscapedPath() apart, stripped a known
// sub-action suffix ("/instantiate", "/validate"), PathUnescape'd the remainder
// into an id, and dispatched on r.Method inside each of three branches. The
// seven routes below are that fan-out, written down.
//
// # ⛔ The blocker this step cleared, and the decision behind it
//
// A template id is a file stem under the registry's templates directory
// (internal/core/registry/file_source.go relPathIdentity), so shipped ids are
// "evm/erc20" and "evm/polymarket_v2": the slash is part of the id. Go's
// ServeMux splits the *escaped* path on literal '/' and unescapes each segment
// afterwards, so "{id}" carries "evm%2Ferc20" perfectly well and PathValue
// returns "evm/erc20" decoded — §2.3 row 2's predicted risk is a net gain, as it
// was for presets. What blocked templates was the opposite problem: half the
// clients sent the id *unencoded*, and then "/api/v1/templates/a/b" is equally
// "template a/b" and "template a, sub-action b", separable only by the suffix
// ladder inside ServeHTTP. Measured on the old handler, GET
// /api/v1/templates/evm/erc20 answered 200 with the template.
//
// The decision (recorded by the maintainer) was option (a): every client
// percent-encodes. It landed as its own change *before* this one, against the
// unchanged server, because the old server accepted both forms and the new one
// accepts only the encoded form — doing it the other way round opens a window
// where live clients send a raw slash to a daemon that has stopped taking it.
// pkg/client (url.PathEscape) and pkg/rs-client (urlencoding::encode) always
// encoded; pkg/js-client, extension/background.js and the two e2e call sites did
// not and now do.
//
// ⚠️ Who still breaks, stated rather than buried: remote-signer-client published
// on npm at 0.0.5 (vendored under pkg/mcp-server/node_modules, which
// pkg/mcp-server calls), and any extension bundle deployed from before that
// change. Both send "/api/v1/templates/evm/erc20" and get the /api/v1/ JSON 404
// from a daemon built here. That is the accepted cost of (a), and it is why the
// two ways out that keep them working — depth-bounded compatibility patterns, or
// leaving the sub-tree on a prefix forever — were considered and rejected.
// ⛔ A 308 redirect is not a fourth option: middleware/auth.go signs
// r.URL.EscapedPath(), so a client replaying its headers at the redirect target
// would 401 on every request.
//
// # ⛔ Permissions: copied verbatim, and four of them are newly visible debt
//
// All eight carry Permitted(PermReadTemplates), byte for byte what the prefixes
// declared. ⚠️ Four are mutating routes on a read permission and appear in
// scripts/lib/arch-baseline/ast/route-mutating-perm.txt for the first time:
// create, update, delete and instantiate. That is newly **visible** pre-existing
// debt, not a change made here — a method-less prefix is something
// route-mutating-perm cannot see at all (its own baseline says so), and those
// four endpoints have always been reachable holding only read_templates.
//
// ⚠️ And the reason is not "the real check is elsewhere": router.go's comment
// claimed "mutate: PermInstantiateTemplate checked in handler", and that was
// false. PermInstantiateTemplate is defined and granted (middleware/rbac.go:42,
// :103, :153) and checked *nowhere* — grep the tree. ⛔ Fixing that is a security
// decision and its own PR (proposal §2.5 names "the decomposition quietly
// changed a permission" as the single semantically irreversible risk in this
// plan, and that applies in both directions).
//
// ⚠️ validate keeps its admin *role* check inside the handler. RouteAuth carries
// a permission, not a role, so the route layer cannot express it.
// TestTemplateRoutes_RegistersExactlyTheProductionPatterns asserts the pattern
// *and* its authorization for all eight.
//
// ⚠️ Client-visible answers that changed, measured on both sides — the before
// column against the old ServeHTTP, the after column against these patterns
// beside the real registerAPIFallback. Every "404 JSON (fallback)" row is
// {"error":"not found: no such API endpoint"} with a credential, 401 without:
//
//	request                                             before                     after
//	GET    /api/v1/templates/evm/erc20   (unencoded)    200 the template           404 JSON (fallback)
//	POST   /api/v1/templates/evm/erc20/instantiate      the instantiate ran        404 JSON (fallback)
//	POST   /api/v1/templates/evm/agent/validate         the validation ran         404 JSON (fallback)
//	GET    /api/v1/templates/                           200 the list               404 JSON (fallback)
//	POST   /api/v1/templates/                           the create ran             404 JSON (fallback)
//	GET    /api/v1/templates/{id}/                      404 "template not found"   404 JSON (fallback)
//	POST   /api/v1/templates/{id}/instantiate/          405 method not allowed     404 JSON (fallback)
//	POST   /api/v1/templates/{id}/validate/             405 method not allowed     404 JSON (fallback)
//	GET    /api/v1/templates/a/b/c/d                    404 "template not found"   404 JSON (fallback)
//	GET    /api/v1/templates/{id}/unknown               404 "template not found"   404 JSON (fallback)
//	POST   /api/v1/templates/a/b/c/instantiate          the instantiate ran on "a/b/c"  404 JSON (fallback)
//	PUT    /api/v1/templates                            405 method not allowed     404 JSON (fallback)
//	POST   /api/v1/templates/{id}                       405 method not allowed     404 JSON (fallback)
//	GET    /api/v1/templates/{id}/instantiate           405 method not allowed     404 JSON (fallback)
//	GET    /api/v1/templates/{id}/validate              405 method not allowed     404 JSON (fallback)
//	HEAD   /api/v1/templates                            405 method not allowed     200, empty body
//	GET    /api/v1/templates/instances/{id}             404 "template not found"   404 JSON (fallback)
//
// ⚠️ Rows 1–3 are the ones the client change bought, and the only ones that
// withdraw a working call: an unencoded id is no longer a legal URL. Every
// in-repo client now sends %2F (the e2e suite is the running proof — both
// template-validate tests pass through these routes).
//
// ⚠️ Rows 4–5 are the trailing-slash lesson in the *forgiving* direction:
// ServeHTTP did TrimPrefix("/api/v1/templates") then TrimPrefix("/"), so
// "/api/v1/templates/" was indistinguishable from the collection and a POST to
// it created a template. Go's mux never strips a trailing slash, so it is
// unmatched now. No in-repo client sends it.
//
// ⚠️ Row 11 is the S4 swallow again, and the worst row in the table: TrimPrefix
// plus TrimSuffix accepted any depth, so a path three segments deeper than the
// endpoint reached instantiateTemplate with templateID "a/b/c". {id} is exactly
// one segment, so it is unrepresentable now.
//
// ⛔ Rows 12–15 are stated as status changes, not as a hole being closed. Unlike
// presets, signers and hd-wallets, ServeHTTP *did* check the method before every
// mutation — all three of its branches had a 405 default — so no verb ever
// reached a write it should not have. Checked against the real registrations
// before the change: POST on an item, GET on instantiate and GET on validate all
// answered 405 and mutated nothing. What this step removes is the ambiguity and
// the depth swallow; the method guards were already correct and are now
// unrepresentable rather than merely written down.
//
// ⚠️ The HEAD row is a *widening* and is stated rather than hidden: Go's mux
// matches HEAD against a GET pattern and net/http drops the body, so HEAD on the
// collection now reaches ListTemplates where it used to reach ServeHTTP's 405.
// It is a pure read. The same thing happened to settings in S5 and presets in
// S6's first half.
//
// ⚠️ The last row is the one shape that got *better* rather than merely
// different: "/api/v1/templates/instances/{id}" used to be read as a template
// whose id was "instances/{id}", so it answered "template not found" — a message
// about the wrong resource. Nothing claims it now.
func (m *templatesModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) is written out at each call rather than hoisted into a
	// local: cmd/archcheck reads these registrations syntactically, and a
	// variable in the argument slot is a value it cannot resolve — the route
	// gates (route-perm-binding, route-mutating-perm) would silently stop
	// seeing these routes' permission.
	reg.Handle("GET /api/v1/templates", Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.ListTemplates))
	reg.Handle("POST /api/v1/templates", Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.CreateTemplate))
	reg.Handle("GET /api/v1/templates/{id}", Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.GetTemplate))
	reg.Handle("PATCH /api/v1/templates/{id}", Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.UpdateTemplate))
	reg.Handle("DELETE /api/v1/templates/{id}", Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.DeleteTemplate))
	reg.Handle("POST /api/v1/templates/{id}/instantiate", Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.InstantiateTemplate))
	reg.Handle("POST /api/v1/templates/{id}/validate", Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.ValidateTemplate))

	// The instances sub-tree. ⚠️ Its wildcard is a rule id, not a file stem:
	// instance ids are minted as "inst_" + hex
	// (internal/core/service/template.go), never contain a slash, and every
	// caller — pkg/client, pkg/js-client, web/src/pages/Rules.tsx — passes one
	// straight through. That is why this one route could be named a step before
	// the other seven.
	reg.Handle("POST /api/v1/templates/instances/{ruleID}/revoke",
		Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.RevokeInstance))
}
