package api

import (
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// apiKeyNamesExemption is the written reason on GET /api/v1/api-keys/names, and
// it is the exemption itself rather than a comment about one — route_auth.go's
// AuthenticatedOnly refuses an empty one, and
// scripts/lib/arch-baseline/ast/route-auth-exemptions.txt ratchets the line it
// produces.
//
// ⛔ Reproduced byte for byte from where it stood in router.go before S4.
// Decomposing the API-key surface may not change what any of its routes declares
// about authorization, and this string is what that one declares.
const apiKeyNamesExemption = "deliberately weaker than the PermManageAPIKeys surface it sits inside, and the callers are known: " +
	"the Web UI resolves its own key's role through it (web/src/lib/rbac.ts:8-11) and the extension " +
	"fills the grant-access and signer-filter dropdowns (extension/background.js:2680-2692) — both from " +
	"keys that are not the caller's. The projection is id+name+role+enabled over enabled keys only " +
	"(handler/apikey.go:231-254) — no public key, no material, no ability to mutate. " +
	"⚠️ It does disclose the roster of key names and roles to any authenticated key; that is the " +
	"trade this route was created to make, and it is the one to revisit first if it turns out to be wrong."

// apiKeysModule serves API key management plus the name projection.
//
// # Why it is a module (proposal S4, copying S3's shape)
//
// A module is what lets a test drive the *production* route patterns. Routes()
// is exported and RouteRegistrar is an interface, so internal/api/handler's
// external test package (package handler_test — an in-package test cannot import
// internal/api, which imports handler) can hand in a registrar of its own and
// get these patterns into a bare http.ServeMux. A mux built in a fixture with
// the patterns typed in by hand is a second source of truth that stays green
// while describing routes the daemon does not serve.
//
// ⚠️ Like hdWalletsModule and unlike walletsModule it is handed an
// already-constructed handler. NewAPIKeyHandler takes a live read-only predicate
// and is then fed an audit logger and the access service, all read off Router
// state; moving that wiring here would move three Router internals with it and
// has no bearing on the route table. This PR's claim is only that the five
// endpoints below serve what the two prefix patterns did.
type apiKeysModule struct {
	h *handler.APIKeyHandler
}

// NewAPIKeysModule wraps a constructed API key handler. It errors rather than
// registering routes that would nil-panic on the first request.
func NewAPIKeysModule(h *handler.APIKeyHandler) (Module, error) {
	if h == nil {
		return nil, fmt.Errorf("api key handler is required")
	}
	return &apiKeysModule{h: h}, nil
}

func (m *apiKeysModule) Name() string { return "api-keys" }

// Routes registers the API key surface: six endpoints, named (proposal S4).
//
// # What changed and what did not
//
// This used to be three patterns, two of them method-less prefixes:
//
//	GET /api/v1/api-keys/names   (AuthenticatedOnly, the projection)
//	/api/v1/api-keys             (any method → ServeHTTP, switch on r.Method)
//	/api/v1/api-keys/            (any method → ServeKeyHTTP, TrimPrefix for the id)
//
// ⛔ Permissions are byte for byte what those patterns declared: the five
// management endpoints are Permitted(PermManageAPIKeys), and /names keeps its
// AuthenticatedOnly with the same written reason (apiKeyNamesExemption).
// Decomposition *creates* the opportunity to give each endpoint the permission
// it deserves — ⚠️ but that is a security decision, not a refactor, and proposal
// §2.5 records "the decomposition quietly changed a permission" as the one
// semantically irreversible risk in this plan: too strict shows up in e2e, too
// loose does not. TestAPIKeyRoutes_RegistersExactlyTheProductionPatterns asserts
// the pattern *and* its authorization for all six.
//
// ⭐ /names no longer depends on registration order. The comment that used to
// stand at its registration said it "must land BEFORE the /api/v1/api-keys/
// prefix so the standard mux's longest-match wins" — that was true of the
// pre-1.22 mux and is not how Go decides any more: a literal segment beats a
// wildcard segment regardless of registration order, so `GET
// /api/v1/api-keys/names` wins over `GET /api/v1/api-keys/{id}` on its own
// terms. Measured, not assumed. ⚠️ Order is still preserved in the list below
// because the pattern assertion reads it, not because the mux cares.
//
// ⚠️ Client-visible answers that changed, all consequences of the mux taking
// over dispatch — the "after" column is the /api/v1/ fallback's envelope,
// {"error":"not found: no such API endpoint"}:
//
//	request                            before                      after
//	GET    /api/v1/api-keys/           400 "API key ID is required" 404 JSON (fallback)
//	GET    /api/v1/api-keys/{id}/      404 "API key not found"      404 JSON (fallback)
//	GET    /api/v1/api-keys/a/b        404 "API key not found"      404 JSON (fallback)
//	PATCH  /api/v1/api-keys/{id}       405 method not allowed       404 JSON (fallback)
//	PUT    /api/v1/api-keys            405 method not allowed       404 JSON (fallback)
//
// The first row is the handler's own "API key ID is required" guard, which only
// existed because a prefix pattern let a request with no id reach a handler at
// all: a {id} wildcard does not match an empty segment, so nothing reaches the
// handler now. ⚠️ Rows 2 and 3 were already 404 — TrimPrefix handed the handler
// "{id}/" and "a/b" as *the id* and the repository lookup missed. So an id with
// a slash in it could never have worked, which is also why %2F is a non-issue
// here: createAPIKey rejects any id outside ^[a-zA-Z0-9-]+$.
//
// A wrong method was the handler's 405 JSON. Because "/api/v1/" matches every
// method, such a request reaches the fallback and answers 404 instead. ⚠️ This
// is proposal §0 correction 9 arriving for real, and note it is NOT what the
// bare test mux answers: with no fallback registered the mux itself answers 405,
// so the package's 405 assertions still pass while a daemon says 404.
//
// ⛔ Do not "fix" any of these by adding "/api/v1/api-keys/" back. It would
// restore the prefix's habit of answering for paths that are not API-key
// endpoints, which is the property being removed.
func (m *apiKeysModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) / AuthenticatedOnly(...) are written out at each call
	// rather than hoisted into a local: cmd/archcheck reads these registrations
	// syntactically, and a variable in the argument slot is a value it cannot
	// resolve — the route gates would silently stop seeing these routes'
	// permission. (A package-level const it can resolve, which is what
	// apiKeyNamesExemption is.)
	reg.Handle("GET /api/v1/api-keys/names", AuthenticatedOnly(apiKeyNamesExemption), http.HandlerFunc(m.h.ListAPIKeyNames))
	reg.Handle("GET /api/v1/api-keys", Permitted(middleware.PermManageAPIKeys), http.HandlerFunc(m.h.ListAPIKeys))
	reg.Handle("POST /api/v1/api-keys", Permitted(middleware.PermManageAPIKeys), http.HandlerFunc(m.h.CreateAPIKey))
	reg.Handle("GET /api/v1/api-keys/{id}", Permitted(middleware.PermManageAPIKeys), http.HandlerFunc(m.h.GetAPIKey))
	reg.Handle("PUT /api/v1/api-keys/{id}", Permitted(middleware.PermManageAPIKeys), http.HandlerFunc(m.h.UpdateAPIKey))
	reg.Handle("DELETE /api/v1/api-keys/{id}", Permitted(middleware.PermManageAPIKeys), http.HandlerFunc(m.h.DeleteAPIKey))
}
