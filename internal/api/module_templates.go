package api

import (
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// templatesModule serves the template *instance* sub-tree.
//
// ⛔ ONE ROUTE, AND THE REASON IT IS ONLY ONE IS THE POINT OF THIS COMMENT.
//
// Proposal S6 is "template.go + the instances closure, ≥8 endpoints". The
// closure is gone — that is the route below. The other seven endpoints
// (collection GET/POST and, under an id, GET/PATCH/DELETE/instantiate/validate)
// are still served by the two prefix patterns in setupRoutes, and they stay
// there until somebody decides the question in the next paragraph. ⛔ Do not
// read this file as "S6 landed".
//
// # The blocker, measured
//
// §2.3 row 2 predicted %2F would be the risk here and guessed the wrong
// direction. Go's ServeMux splits the *escaped* path on literal '/' and
// unescapes each segment afterwards, so a wildcard segment carries "evm%2Fweth"
// perfectly well and PathValue returns "evm/weth" decoded. That half is a net
// gain and the preset routes take it (module_presets.go).
//
// What actually blocks templates is the opposite: half the clients send the id
// *unencoded*. Template ids are file stems under rules/templates
// (internal/core/registry/file_source.go relPathIdentity), so a shipped id is
// "evm/erc20" or "evm/polymarket_v2" — and:
//
//	pkg/client/templates/templates.go        url.PathEscape      → evm%2Ferc20
//	pkg/rs-client/src/templates/templates.rs urlencoding::encode → evm%2Ferc20
//	pkg/js-client/src/templates/index.ts     `${templateID}` raw → evm/erc20
//	extension/background.js                  raw (bundled copy)  → evm/erc20
//	web/src (via the js-client symlink)      raw                 → evm/erc20
//	e2e/e2e_polymarket_test.go:56            raw concat          → evm/polymarket_v2
//
// ⚠️ Note pkg/js-client encodes for *presets* and not for *templates*, in
// sibling files. So the Web UI shipped inside this binary reaches a registry
// template's detail, instantiate and validate endpoints over paths like
// /api/v1/templates/evm/erc20 and /api/v1/templates/evm/erc20/instantiate.
//
// ⛔ With an unencoded slash allowed in an id, the URL grammar is ambiguous and
// no route table can name these endpoints: "/api/v1/templates/a/b" is both
// "template a/b" and "template a, sub-action b", and only a list of known
// suffixes tells them apart — which is exactly the TrimSuffix ladder inside
// TemplateHandler.ServeHTTP. Registering `GET /api/v1/templates/{id}` alone
// does not truncate those ids, it stops matching them: the Web UI's template
// page, the JS SDK, the extension and two e2e tests would get the /api/v1/
// 404. So the decomposition of the id-carrying template routes is blocked on a
// decision that is not a refactor:
//
//	(a) make every client percent-encode — fixes web/src and pkg/js-client in
//	    this repo, but breaks already-published remote-signer-client versions
//	    and any deployed extension bundle against a new daemon;
//	(b) register depth-bounded compatibility patterns
//	    (`GET /api/v1/templates/{a}/{b}`, `POST /api/v1/templates/{a}/{b}/instantiate`,
//	    …) — keeps every client working and names every endpoint, at the price
//	    of writing today's two-level catalogue layout into the route table and
//	    doubling the OpenAPI path count;
//	(c) leave the id sub-tree on a prefix and accept that those endpoints get no
//	    honest annotation (proposal §3.3 forbids annotating them either way).
//
// ⛔ A 308 redirect from the unencoded form to the encoded one is NOT a fourth
// option: middleware/auth.go signs r.URL.EscapedPath(), so a client replaying
// its headers against the redirect target would 401 on every request.
//
// # Why the instances route could go anyway
//
// Its wildcard is a rule id, not a file stem: instance ids are minted as
// "inst_" + hex (internal/core/service/template.go:757), never contain a slash,
// and every caller — pkg/client, pkg/js-client, web/src/pages/Rules.tsx —
// passes one straight through. Nothing here has to decide the question above.
type templatesModule struct {
	h *handler.TemplateHandler
}

// NewTemplatesModule wraps a constructed template handler. It errors rather
// than registering a route that would nil-panic on the first request.
func NewTemplatesModule(h *handler.TemplateHandler) (Module, error) {
	if h == nil {
		return nil, fmt.Errorf("template handler is required")
	}
	return &templatesModule{h: h}, nil
}

func (m *templatesModule) Name() string { return "templates" }

// Routes registers the one template endpoint this step could name.
//
// # What changed and what did not
//
// The endpoint used to be reached through a closure registered inline in
// setupRoutes:
//
//	r.handle("/api/v1/templates/", Permitted(PermReadTemplates), http.HandlerFunc(func(w, req) {
//	    if strings.HasPrefix(req.URL.Path, "/api/v1/templates/instances/") {
//	        templateHandler.ServeInstanceHTTP(w, req)
//	        return
//	    }
//	    templateHandler.ServeHTTP(w, req)
//	}))
//
// — a route whose handler was an anonymous function that dispatched on a path
// prefix, i.e. a second route table hidden inside the first one, invisible to
// every gate that reads registrations. ServeInstanceHTTP then did its own
// TrimPrefix/HasSuffix/method check. All of that is replaced by the pattern
// below plus TemplateHandler.RevokeInstance reading r.PathValue("ruleID").
//
// ⛔ PermReadTemplates is copied verbatim from the prefix this came out of.
// ⚠️ It is a *mutating* route on a *read* permission, so it appears in
// scripts/lib/arch-baseline/ast/route-mutating-perm.txt for the first time.
// That is newly **visible** pre-existing debt, not a change made here — the
// prefix carried PermReadTemplates and served this revoke all along; a
// method-less prefix is simply something route-mutating-perm cannot see (its
// own baseline says so). ⛔ Fixing it is a security decision and belongs in its
// own PR (proposal §2.5).
//
// ⚠️ Client-visible answers that changed, measured on both sides:
//
//	request                                            before                  after
//	GET  /api/v1/templates/instances/{id}/revoke       405 method not allowed  404 "template not found"
//	POST /api/v1/templates/instances/{id}              404 "not found"         405 "method not allowed"
//	POST /api/v1/templates/instances/a/b/revoke        the revoke ran on "a/b" 405 "method not allowed"
//	POST /api/v1/templates/instances/{id}/revoke/      404 "not found"         405 "method not allowed"
//
// ⚠️ Read the "after" column carefully: none of these is the /api/v1/ fallback.
// The `/api/v1/templates/` prefix is still registered (see the blocker above),
// so anything under it that this one route does not claim still lands in
// TemplateHandler.ServeHTTP, which takes the whole remainder as a template id —
// a GET then reports no such template, and a POST falls through its method
// switch to 405. Both are *worse* answers than the fallback's, and both go away
// when the id sub-tree is decomposed; neither is something this step can fix on
// its own.
//
// ⚠️ Row 3 is the S4 swallow again: TrimPrefix + TrimSuffix accepted any depth,
// so a path two segments deeper than the endpoint revoked rule "a/b". Nothing
// mints such an id, so nothing was reachable through it; it is closed now
// because {ruleID} is exactly one segment.
func (m *templatesModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) is written out at the call rather than hoisted into a
	// local: cmd/archcheck reads these registrations syntactically, and a
	// variable in the argument slot is a value it cannot resolve — the route
	// gates would silently stop seeing this route's permission.
	reg.Handle("POST /api/v1/templates/instances/{ruleID}/revoke",
		Permitted(middleware.PermReadTemplates), http.HandlerFunc(m.h.RevokeInstance))
}
