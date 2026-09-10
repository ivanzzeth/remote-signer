package api

import (
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// settingsModule serves the runtime-mutable configuration groups: nine groups,
// each readable and writable, as eighteen named routes.
//
// # Why it is a module (proposal S5, copying S3/S4's shape)
//
// A module is what lets a test drive the *production* route patterns. Routes()
// is exported and RouteRegistrar is an interface, so internal/api/handler's
// external test package (package handler_test — an in-package test cannot
// import internal/api, which imports handler) can hand in a registrar of its
// own and get these patterns into a bare http.ServeMux. A mux built in a
// fixture with the patterns typed in by hand is a second source of truth that
// stays green while describing routes the daemon does not serve.
//
// ⚠️ Like hdWalletsModule, apiKeysModule and signersModule, and unlike
// walletsModule, it is handed an already-constructed handler: the router feeds
// the settings handler its audit logger and its syncApprovalGuard hook, both
// read off Router state, and moving that wiring here would move two Router
// internals with it for no gain in the route table.
type settingsModule struct {
	h *handler.SettingsHandler
}

// NewSettingsModule wraps a constructed settings handler. It errors rather than
// registering routes that would nil-panic on the first request.
func NewSettingsModule(h *handler.SettingsHandler) (Module, error) {
	if h == nil {
		return nil, fmt.Errorf("settings handler is required")
	}
	return &settingsModule{h: h}, nil
}

func (m *settingsModule) Name() string { return "settings" }

// Routes registers the settings surface: eighteen endpoints, named (proposal S5).
//
// # ⭐ What this step is for, and why literal-per-group rather than {group}
//
// This used to be one pattern:
//
//	/api/v1/admin/settings/    (any method, any depth) (PermManageSettings)
//
// behind which SettingsHandler.ServeHTTP cut the group out of r.URL.Path and
// switched on it twice — once to choose which snapshot to return, once to
// choose which struct to decode the request body into. ⛔ The second switch is
// the shape OpenAPI cannot express: a spec has one requestBody schema per
// path+method, and here the schema is selected by a *value inside the path*.
// Nine groups, nine unrelated body types, one path.
//
// ⛔ A single `PUT /api/v1/admin/settings/{group}` route would NOT fix that. It
// would move the switch from the handler to the route table while the body type
// still varied with a path value — the surface would read as decomposed and
// stay un-describable. So each group gets its own literal path and its own
// concrete body type, and the "18 endpoints behind 1 pattern" row in proposal
// §1.2 becomes 18 patterns. There is no group dispatch left to make that
// impractical: the group identifiers are compile-time constants in
// internal/settings/model.go, they contain dots but never slashes, so each is
// one literal path segment.
//
// ⛔ Permissions are byte for byte what the single pattern declared: all
// eighteen are Permitted(PermManageSettings), which is what
// "/api/v1/admin/settings/" declared for every one of the endpoints it hid.
// Decomposition *creates* the opportunity to give reads a weaker permission
// than writes — ⚠️ but that is a security decision, not a refactor, and
// proposal §2.5 records "the decomposition quietly changed a permission" as the
// one semantically irreversible risk in this plan: too strict shows up in e2e,
// too loose does not. TestSettingsRoutes_RegistersExactlyTheProductionPatterns
// asserts the pattern *and* its authorization for all eighteen.
//
// ⚠️ Client-visible answers that changed. Both columns are *measured* — the
// before column against the old registration and the old handler, the after
// column against this module next to the real registerAPIFallback — not read
// off the code. Every path in the table now dispatches to "/api/v1/", whose
// answer is {"error":"not found: no such API endpoint"} with a credential and
// 401 without one:
//
//	request                                        before                                after
//	GET    /api/v1/admin/settings/security/        400 "group required: …"               404 JSON (fallback)
//	PUT    /api/v1/admin/settings/security/        400 "group required: …"               404 JSON (fallback)
//	GET    /api/v1/admin/settings/                 400 "group required: …"               404 JSON (fallback)
//	GET    /api/v1/admin/settings/security/extra   400 "group required: …"               404 JSON (fallback)
//	GET    /api/v1/admin/settings/a/b/c/d          400 "group required: …"               404 JSON (fallback)
//	GET    /api/v1/admin/settings/unknown.group    404 "unknown settings group: …"       404 JSON (fallback)
//	PUT    /api/v1/admin/settings/unknown.group    400 "unknown or read-only …"          404 JSON (fallback)
//	POST   /api/v1/admin/settings/security         405 "method not allowed"              404 JSON (fallback)
//	DELETE /api/v1/admin/settings/security         405 "method not allowed"              404 JSON (fallback)
//	PATCH  /api/v1/admin/settings/security         405 "method not allowed"              404 JSON (fallback)
//	GET    /api/v1/admin/settings                  301 → /api/v1/admin/settings/         404 JSON (fallback)
//	PUT    /api/v1/admin/settings                  301 → /api/v1/admin/settings/         404 JSON (fallback)
//
// ⭐ One row goes the other way — a shape that used to be refused and is now
// served, the only one in this table:
//
//	HEAD   /api/v1/admin/settings/<group>   405 "method not allowed"   200, GET's body
//
// Go's ServeMux matches a HEAD request against a GET pattern, and net/http
// discards the body on the way out. The old switch had no HEAD arm so it fell to
// the 405 default. ⚠️ This is a widening, so it is worth stating plainly rather
// than filing under "the mux decides methods now": nothing in the repo sends
// HEAD, all nine GET endpoints are pure reads, and answering HEAD like GET is
// what HTTP says to do — but it was measured, not assumed, and
// TestSettingsRoutes_HeadIsServedByTheGetRoute pins both halves (it reaches the
// GET route, and it cannot write).
//
// ⭐ Two things this surface did NOT have, stated because the three modules
// before it did and the difference is the interesting part:
//
//  1. **No verb hole.** ServeHTTP dispatched on `switch r.Method` with a 405
//     default, so GET/POST/DELETE/PATCH never mutated anything — measured, at
//     HEAD, by driving each verb at a real manager and reading the snapshot
//     back. That is why this step closes no defect the way 6d30ba1/8e82a82 did;
//     what it closes is the schema hole above.
//  2. **No swallow.** The `strings.Contains(group, "/")` guard rejected every
//     deep path with 400, so nothing like the signers' `.../access/a/b`
//     returning a real access list existed here.
//
// ⚠️ Trailing slash, in the direction opposite to hd-wallets. ServeHTTP did NOT
// run TrimSuffix, so ".../security/" left "security/" as the group, the slash
// guard caught it and answered 400. It was already refused; what changes is the
// status and the body, not the effect. ⛔ No client sends it: pkg/client's
// clientsettings, pkg/js-client's SettingsService, web/src (through js-client)
// and extension/background.js all build the path as prefix + group with nothing
// after it.
//
// ⚠️ Row 11-12 are not 405 becoming 404: they were **301 redirects**. ServeMux
// redirects a path with no match to the subtree pattern one level up, and
// "/api/v1/admin/settings/" was such a pattern, so a request to the collection —
// with any verb, PUT included — was bounced into the prefix and answered 400
// there. With the prefix gone there is nothing to redirect to.
//
// ⚠️ These are proposal §0 correction 9 arriving for real, and note they are NOT
// what a bare test mux answers: with no "/api/v1/" in the way the mux answers
// its own 404, or 405 where a sibling method is registered on the same path.
//
// ⛔ Do not "fix" any of these by adding "/api/v1/admin/settings/" back. It is
// the pattern this step exists to remove.
func (m *settingsModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) is written out at each call rather than hoisted into a
	// local: cmd/archcheck reads these registrations syntactically, and a
	// variable in the argument slot is a value it cannot resolve — the route
	// gates (route-perm-binding, route-mutating-perm) would silently stop
	// seeing these routes' permission.
	//
	// ⚠️ The literal group segments are spelled out rather than built from
	// settings.Group constants for the same reason: archcheck resolves a string
	// literal and cannot resolve a concatenation, and a pattern it cannot read
	// is a pattern the permission ratchet stops watching. That was measured on
	// this repo once already — the four signer actions were built by string
	// concatenation in a loop and route-mutating-perm recorded them as a single
	// unparseable `…/{address}/*` row (proposal §0 correction 2).
	reg.Handle("GET /api/v1/admin/settings/security", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetSecurity))
	reg.Handle("PUT /api/v1/admin/settings/security", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutSecurity))
	reg.Handle("GET /api/v1/admin/settings/notify", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetNotify))
	reg.Handle("PUT /api/v1/admin/settings/notify", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutNotify))
	reg.Handle("GET /api/v1/admin/settings/audit_monitor", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetAuditMonitor))
	reg.Handle("PUT /api/v1/admin/settings/audit_monitor", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutAuditMonitor))
	reg.Handle("GET /api/v1/admin/settings/evm.dynamic_blocklist", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetBlocklist))
	reg.Handle("PUT /api/v1/admin/settings/evm.dynamic_blocklist", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutBlocklist))
	reg.Handle("GET /api/v1/admin/settings/evm.simulation", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetSimulation))
	reg.Handle("PUT /api/v1/admin/settings/evm.simulation", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutSimulation))
	reg.Handle("GET /api/v1/admin/settings/evm.foundry", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetFoundry))
	reg.Handle("PUT /api/v1/admin/settings/evm.foundry", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutFoundry))
	reg.Handle("GET /api/v1/admin/settings/evm.rpc_gateway", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetRPCGateway))
	reg.Handle("PUT /api/v1/admin/settings/evm.rpc_gateway", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutRPCGateway))
	reg.Handle("GET /api/v1/admin/settings/evm.material_check", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetMaterialCheck))
	reg.Handle("PUT /api/v1/admin/settings/evm.material_check", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutMaterialCheck))
	reg.Handle("GET /api/v1/admin/settings/web", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.GetWeb))
	reg.Handle("PUT /api/v1/admin/settings/web", Permitted(middleware.PermManageSettings), http.HandlerFunc(m.h.PutWeb))
}
