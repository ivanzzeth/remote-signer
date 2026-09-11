package api

import (
	"fmt"

	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// requestsModule serves the sign-request surface: the list, one request, the two
// per-request actions, batch approval, and the simulation a request produced.
//
// # Why it is a module (proposal S7, copying S3–S6's shape)
//
// A module is what lets a test drive the *production* route patterns. Routes() is
// exported and RouteRegistrar is an interface, so internal/api/handler/evm's
// external test package (package evm_test — an in-package test cannot import
// internal/api, which imports the handler package) can hand in a registrar of its
// own and get these patterns into a bare http.ServeMux. A mux built in a fixture
// with the patterns typed in by hand is a second source of truth that stays green
// while describing routes the daemon does not serve.
//
// ⚠️ Like the signers, settings, presets and templates modules it is handed
// already-constructed handlers: they need the sign service, the rule repository,
// the signer access service and two repositories, all of which setupRoutes builds
// from Router state. Moving that wiring here would move Router internals with it
// and has no bearing on the route table.
//
// ⚠️ Unlike those four, this module wraps *six handlers rather than one*, because
// the surface was never one handler: the prefix fanned out to four different
// types. That is also why each endpoint function below is the handler's own
// ServeHTTP rather than a named method — every one of these handlers serves
// exactly one endpoint, which is the shape `POST /api/v1/evm/requests/batch-approve`
// already had before this step.
type requestsModule struct {
	list       *evmhandler.ListHandler
	detail     *evmhandler.RequestHandler
	approval   *evmhandler.ApprovalHandler
	batch      *evmhandler.BatchApprovalHandler
	preview    *evmhandler.PreviewRuleHandler
	simulation *evmhandler.RequestSimulationHandler
}

// NewRequestsModule wraps the constructed request handlers. It errors rather than
// registering routes that would nil-panic on the first request.
//
// ⭐ All six parameters are distinct types, so handing them over in the wrong
// order — the one mistake a six-argument constructor invites, and the one that
// would put the approval handler on the preview route — does not compile.
//
// ⚠️ simulation is the one optional dependency, and it is optional in production:
// setupRoutes only builds a RequestSimulationHandler when RouterConfig has both
// RequestSimulationRepo and RequestRepo (e2e/test_server.go, for one, sets
// neither). nil means the route is not registered, so the path reaches the
// /api/v1/ JSON 404 fallback. ⚠️ That replaces a plain-text "404 page not found"
// the closure wrote itself — measured; it is the one answer in this step that got
// *better* for a JSON client rather than merely different.
func NewRequestsModule(
	list *evmhandler.ListHandler,
	detail *evmhandler.RequestHandler,
	approval *evmhandler.ApprovalHandler,
	batch *evmhandler.BatchApprovalHandler,
	preview *evmhandler.PreviewRuleHandler,
	simulation *evmhandler.RequestSimulationHandler,
) (Module, error) {
	switch {
	case list == nil:
		return nil, fmt.Errorf("list handler is required")
	case detail == nil:
		return nil, fmt.Errorf("request handler is required")
	case approval == nil:
		return nil, fmt.Errorf("approval handler is required")
	case batch == nil:
		return nil, fmt.Errorf("batch approval handler is required")
	case preview == nil:
		return nil, fmt.Errorf("preview rule handler is required")
	}
	return &requestsModule{
		list:       list,
		detail:     detail,
		approval:   approval,
		batch:      batch,
		preview:    preview,
		simulation: simulation,
	}, nil
}

func (m *requestsModule) Name() string { return "requests" }

// ---------- the two exemptions, verbatim ----------
//
// ⛔ These are halves of one reason string that stood on the prefix, split so
// that each says what is true of the endpoint it is attached to and nothing
// else. The prefix's text claimed both remaining branches "answer 404 rather than
// 403 for a foreign id"; that is true of the simulation endpoint and **false** of
// the detail endpoint, which answers 403 (handler/evm/request.go's getRequest,
// asserted by TestB3RequestHandler_NonAdminOwnershipCheck). Splitting the reason
// is what made the discrepancy visible. ⛔ Nothing here changes either answer —
// making them agree is a decision about id enumeration, not part of a
// decomposition.
const (
	requestDetailRowScope = "per-row, not per-route: any authenticated caller may fetch a request they " +
		"submitted, and handler/evm/request.go's getRequest is what decides — admin and dev see every row, " +
		"everyone else only rows created with their own API key. A route cannot make that call. " +
		"⚠️ It answers 403 for a foreign id, not 404, so the id space is enumerable by response code; " +
		"⛔ that is pre-existing and is not changed here (the simulation endpoint below answers 404 for " +
		"the same case, and the two have disagreed all along)."

	requestSimulationRowScope = "per-row, not per-route: visibility piggybacks on the parent sign request. " +
		"handler/evm/request_simulation.go re-fetches the parent and answers 404 — not 403 — when the " +
		"caller does not own it, so a probing caller cannot enumerate other operators' request ids by " +
		"watching response codes. A route cannot make that call."
)

// Routes registers the sign-request surface: six endpoints, named (proposal S7).
//
// # What changed and what did not
//
// This used to be two registrations plus one closure:
//
//	/api/v1/evm/requests                      (any method)   Permitted(PermListOwnRequests)
//	POST /api/v1/evm/requests/batch-approve                  Permitted(PermApproveRequest)
//	/api/v1/evm/requests/  (any method, any depth)           AuthenticatedOnly(one long reason)
//
// The third one is the interesting one. It was registered without a method and
// without a sub-path, so it matched every verb at every depth under
// /api/v1/evm/requests/, and an inline closure in setupRoutes then dispatched on
// strings.HasSuffix(r.URL.Path, …) through a ladder of four branches —
// "/approve", "/preview-rule", "/simulation", else the detail handler — wrapping
// two of them in middleware.RequirePermission by hand. Four endpoints behind one
// pattern, a second route table hidden inside the first: nothing that reads
// registrations could see any of it, which is exactly what the ⛔ KNOWN LIMIT
// section of route_auth.go describes.
//
// # ⛔ Permissions and exemptions: copied verbatim, and what each one becomes
//
// ⚠️ Proposal §1.2 counted four sub-endpoints of which only two carried a
// permission. Still true at the time of this change, and here is each one:
//
//	endpoint                                    before                          after
//	GET  /api/v1/evm/requests                   Permitted(PermListOwnRequests)  unchanged, now method-scoped
//	GET  /api/v1/evm/requests/{id}              the prefix's exemption          AuthenticatedOnly(requestDetailRowScope)
//	POST /api/v1/evm/requests/{id}/approve      RequirePermission(PermApproveRequest) in the closure   Permitted(PermApproveRequest)
//	POST /api/v1/evm/requests/{id}/preview-rule RequirePermission(PermPreviewRule) in the closure      Permitted(PermPreviewRule)
//	POST /api/v1/evm/requests/batch-approve     Permitted(PermApproveRequest)   unchanged
//	GET  /api/v1/evm/requests/{id}/simulation   the prefix's exemption          AuthenticatedOnly(requestSimulationRowScope)
//
// ⭐ So the two permissions the closure installed by hand are now declared where
// the route is, and route-perm-binding ratchets them for the first time: the
// closure's RequirePermission calls were invisible to it, and so was the fact
// that two of the four endpoints had no permission at all.
//
// ⚠️ One consequence worth stating because nothing tests it: RequirePermission
// moves *outward* by two middlewares. The closure ran it innermost, after
// RateLimitMiddleware and ContentTypeMiddleware; withAuthAndPerm (route_auth.go)
// runs it before both. So a caller who lacks approve_request and also sends a
// wrong Content-Type now gets 403 where it used to get 415, and a request refused
// for permission no longer consumes a rate-limit token. Same permission, same
// decision, earlier. Every Permitted route in the repo already had this order;
// this makes these two consistent with them.
//
// ⛔ route-mutating-perm gains nothing here, and that is a fact rather than a
// hope: it fires on a mutating pattern gated on a *read* permission, and the
// three mutating routes below carry approve_request and preview_rule, neither of
// which is in cmd/archcheck/routeauth.go's readPermissions.
//
// ⚠️ Client-visible answers that changed, measured on both sides — the before
// column against the real registrations (the prefix claims every shape below;
// TestZZS7Probe recorded which handler ran and what it did), the after column
// against these patterns beside the real registerAPIFallback. Every
// "404 JSON (fallback)" row is {"error":"not found: no such API endpoint"} with a
// credential, 401 without:
//
//	request                                                   before                                   after
//	POST /api/v1/evm/requests/a/b/approve                      200, approved request "b"                404 JSON (fallback)
//	POST /api/v1/evm/requests/a/b/c/d/approve                  200, approved request "d"                404 JSON (fallback)
//	POST /api/v1/evm/requests/approve                          approved request "requests" (404 in prod) 404 JSON (fallback)
//	POST /api/v1/evm/requests/a/b/preview-rule                 200, previewed for request "b"           404 JSON (fallback)
//	GET  /api/v1/evm/requests/a/b/c                            200, request "c"                         404 JSON (fallback)
//	GET  /api/v1/evm/requests/{id}/unknown                     200, request "unknown"                   404 JSON (fallback)
//	GET  /api/v1/evm/requests/                                 read request "" → 404                    404 JSON (fallback)
//	GET  /api/v1/evm/requests/{id}/                            read request "" → 404                    404 JSON (fallback)
//	POST /api/v1/evm/requests/{id}/approve/                    405 (fell out of the ladder)             404 JSON (fallback)
//	GET  /api/v1/evm/requests/{id}/approve                     405 method not allowed                   404 JSON (fallback)
//	DELETE /api/v1/evm/requests/{id}/approve                   405 method not allowed                   404 JSON (fallback)
//	GET  /api/v1/evm/requests/{id}/preview-rule                405 method not allowed                   404 JSON (fallback)
//	POST /api/v1/evm/requests/{id}                             405 method not allowed                   404 JSON (fallback)
//	POST /api/v1/evm/requests/{id}/simulation                  405 method not allowed                   404 JSON (fallback)
//	PUT  /api/v1/evm/requests                                  405 method not allowed                   404 JSON (fallback)
//	GET  /api/v1/evm/requests/{id}/simulation, no repo wired    404 "404 page not found" (text/plain)   404 JSON (fallback)
//	HEAD /api/v1/evm/requests                                  405 method not allowed                   200, empty body
//	HEAD /api/v1/evm/requests/{id}                              405 method not allowed                   200, empty body
//
// ⛔ Rows 1–4 are the ones that mattered, and rows 1 and 2 are a defect rather
// than a status change: the ladder read the id as "the segment before the
// action", so any number of extra segments in front of it was accepted and
// ignored, and the endpoint they reach *mutates*. A caller holding
// approve_request could approve request "b" through a URL naming request "a" —
// the audit log's path and the row that changed disagree. It is not a permission
// bypass (all four branches did check their method, and the closure did install
// approve_request), which is why it is stated as an id/path confusion. {id} is
// one segment, so every one of those shapes now matches no pattern.
//
// ⚠️ GET /api/v1/evm/requests/batch-approve is deliberately absent from the table,
// and measuring it is what kept it out: "batch-approve" is one legal segment, so
// that request matches GET /api/v1/evm/requests/{id} and reads a request with that
// id — which is exactly what the closure's default branch did with it. Unchanged,
// 404 "request not found" either way. ⭐ It is also the one pattern overlap here:
// the literal segment is a strict subset of the wildcard, so Go's mux takes both
// and prefers the literal for POST (proposal §2.2's safe shape, not the panicking
// one). TestRequestRoutes_BatchApproveIsOnlyALiteralForPost pins it.
//
// ⚠️ Rows 5–6 are the same swallow on the read side: "the last segment wins" meant
// /api/v1/evm/requests/{anything}/{id} answered with {id}. Nothing enumerable came
// out of it — the id still had to exist and pass the caller check — so these were
// wrong answers rather than wrong mutations.
//
// ⚠️ Rows 7–8 are the trailing slash, in the *forgiving* direction: the prefix
// matched them, the ladder found no known suffix, and the detail handler took the
// last (empty) segment as the id, so both asked the repository for request "" and
// got 404. Go's mux never strips a trailing slash, so they match nothing now. No
// in-repo client sends either.
//
// ⛔ Rows 9–15 are stated as status changes, not as holes being closed. Unlike
// presets, signers and hd-wallets, all four closure branches *did* check the
// method before doing anything — measured with spies on ProcessApproval and
// PreviewRuleForRequest: every wrong verb answered 405 and called neither. What
// this step removes is the depth swallow and the ambiguity; the method guards
// were already correct and are now unrepresentable rather than merely written
// down.
//
// ⭐ Row 16 is the only answer that got *better*: with no simulation repositories
// wired the closure called http.NotFound itself, which writes text/plain
// "404 page not found" — to a JSON client, on an API path. The route is simply
// absent in that configuration now, so the /api/v1/ JSON 404 answers instead.
//
// ⚠️ The two HEAD rows are a *widening* and are stated rather than hidden: Go's
// mux matches HEAD against a GET pattern and net/http drops the body, so HEAD now
// reaches ListHandler and RequestHandler where the handlers' own method guards
// answered 405. Both are pure reads. The same thing happened to settings in S5
// and to templates and presets in S6.
//
// ⚠️ A request id is a UUID (internal/core/service/sign.go mints
// uuid.New().String() and nothing else creates one), so it contains no '/' and
// the encoding trap that blocked templates for a step does not exist here. Every
// client was checked rather than assumed: pkg/client and pkg/rs-client percent-
// encode it, pkg/js-client, extension/background.js and web/src interpolate it
// raw, pkg/mcp-server uses encodeURIComponent. With a slash-free id all five
// produce the same URL. ⭐ One incidental gain: an id that *did* arrive encoded as
// %2F used to be split on the decoded path (the handler read r.URL.Path), so it
// came out mangled; PathValue decodes the segment and hands over the whole thing.
func (m *requestsModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) and AuthenticatedOnly(...) are written out at each call
	// rather than hoisted into a local: cmd/archcheck reads these registrations
	// syntactically, and a variable in the argument slot is a value it cannot
	// resolve — the route gates (route-perm-binding, route-auth-exempt,
	// route-mutating-perm) would silently stop seeing these routes. A
	// package-level const it can resolve, which is why the two long reasons are
	// consts and the permissions are not.
	reg.Handle("GET /api/v1/evm/requests", Permitted(middleware.PermListOwnRequests), m.list)
	reg.Handle("GET /api/v1/evm/requests/{id}", AuthenticatedOnly(requestDetailRowScope), m.detail)
	reg.Handle("POST /api/v1/evm/requests/{id}/approve", Permitted(middleware.PermApproveRequest), m.approval)
	reg.Handle("POST /api/v1/evm/requests/{id}/preview-rule", Permitted(middleware.PermPreviewRule), m.preview)
	reg.Handle("POST /api/v1/evm/requests/batch-approve", Permitted(middleware.PermApproveRequest), m.batch)

	// ⚠️ Conditional, exactly as the handler's construction is: setupRoutes
	// builds no RequestSimulationHandler unless both RequestSimulationRepo and
	// RequestRepo are wired. ⛔ Registering the route unconditionally and
	// answering 404 inside it would put a route in the table that no deployment
	// without those repos serves — the same "read setupRoutes and you still
	// cannot say what is served" problem the module shape exists to remove.
	if m.simulation != nil {
		reg.Handle("GET /api/v1/evm/requests/{id}/simulation", AuthenticatedOnly(requestSimulationRowScope), m.simulation)
	}
}
