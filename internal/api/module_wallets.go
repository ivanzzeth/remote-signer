package api

import (
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// walletsModule serves wallet CRUD and wallet membership.
//
// # Why this became a module before the handler was decomposed (proposal S2, then S3)
//
// The routes below used to be two r.handle calls sitting inline in setupRoutes:
// "/api/v1/wallets" and "/api/v1/wallets/". S2 moved them here and changed
// nothing about them — same two literal patterns, same Permitted on both — and
// that sameness was the point: it moves the wallet handler tests off direct
// h.ServeHTTP onto a real mux, and a test can only do that honestly if the
// patterns it routes through come from the production registration rather than
// from a copy written into a fixture. A copy stays green while describing routes
// the daemon does not serve, which is the exact failure the archcheck route
// gates exist to prevent. S3 then decomposed those two into the eight below,
// with the whole suite recorded green across S2 — so every test difference S3
// produced is the decomposition's, not the harness's.
//
// A module is what makes that reachable: Routes(reg) is exported, RouteRegistrar
// is an interface, so internal/api/handler's *external* test package
// (package handler_test — an in-package test cannot import internal/api, which
// imports handler) can hand in a registrar of its own and get these patterns
// into a bare http.ServeMux. ⚠️ That test registrar deliberately drops the
// RouteAuth: the middleware chain Permitted() implies starts with
// AuthMiddleware, which refuses any request without signed headers, and the
// wallet tests inject their API key through the request context. Routing is what
// those tests are being moved onto; authorization is asserted by the route_auth
// gates and its baselines, not by them.
//
// ⚠️ Still constructed from RouterConfig.WalletRepo rather than by the
// composition root like bootstrap and transactions, and S3 did not change that
// either: finishing it means deleting three RouterConfig fields and wiring the
// module at every call site of NewRouter, which is a wiring change with no
// bearing on the route table. ⛔ It does not belong in the PR whose entire claim
// is that the eight endpoints below serve exactly what the two patterns did.
type walletsModule struct {
	h *handler.WalletHandler
}

// NewWalletsModule returns nil when there is no wallet repository: a daemon
// without one has no wallets to serve, and saying so here beats a nil check at
// the route.
func NewWalletsModule(
	repo storage.WalletRepository,
	ownershipRepo storage.SignerOwnershipRepository,
	accessRepo storage.SignerAccessRepository,
	log *slog.Logger,
) (Module, error) {
	if repo == nil {
		return nil, nil
	}
	h, err := handler.NewWalletHandler(repo, ownershipRepo, accessRepo, log)
	if err != nil {
		return nil, err
	}
	return &walletsModule{h: h}, nil
}

func (m *walletsModule) Name() string { return "wallets" }

// Routes registers the wallet surface: eight endpoints, named (proposal S3).
//
// # What changed and what did not
//
// This used to be two prefix patterns — "/api/v1/wallets" and
// "/api/v1/wallets/" — behind which WalletHandler switched on r.Method and cut
// r.URL.Path apart to reach the same eight destinations. The eight below are
// that fan-out, written down. Which handler function serves which method and
// sub-path is unchanged; what changed is that the mux decides it instead of the
// handler, so each endpoint is a thing the route table can name, an OpenAPI
// annotation can describe, and an SDK can be generated for.
//
// ⛔ Every one of them is Permitted(PermManageWallets), byte for byte what the
// two patterns declared. Decomposition *creates* the opportunity to give each
// endpoint the permission it actually deserves — reading is not managing, and
// PermManageWallets on GET is plainly loose — ⚠️ but that is a security
// decision, not a refactor, and proposal §2.5 records "the decomposition quietly
// changed a permission" as the one semantically irreversible risk in this plan:
// too strict shows up in e2e, too loose does not. Tightening goes in its own PR,
// argued on its own. TestWalletRoutes_RegistersExactlyTheProductionPatterns
// asserts the pattern *and* its permission for all eight, and is the only thing
// in the wallet family that would notice a change here — none of those tests
// runs the middleware chain.
//
// ⚠️ Four client-visible answers changed, all of them consequences of the mux
// taking over dispatch, none of them avoidable without keeping a prefix pattern
// (which would keep the swallow this step exists to remove). Measured, not
// reasoned about — the daemon column is the /api/v1/ fallback's envelope,
// {"error":"not found: no such API endpoint"}:
//
//	request                                  before            after
//	GET  /api/v1/wallets/a/b/c/d             404 wallet not found   404 JSON (fallback)
//	GET  /api/v1/wallets/{id}/x/y/z          404 not found          404 JSON (fallback)
//	GET  /api/v1/wallets/                    400 wallet ID required 404 JSON (fallback)
//	GET  /api/v1/wallets/{id}/               200 the wallet         404 JSON (fallback)
//	GET  /api/v1/wallets/{id}/members/       200 the members        404 JSON (fallback)
//	DELETE /api/v1/wallets                   405 method not allowed 404 JSON (fallback)
//	POST /api/v1/wallets/{id}                405 method not allowed 404 JSON (fallback)
//
// Deep paths were swallowed by the "/api/v1/wallets/" prefix; they match nothing
// now. ⭐ The /api/v1/ JSON-404 fallback (router.go registerAPIFallback) landed
// ahead of this step for exactly this reason and is what keeps them from
// reaching the SPA and answering text/html.
// TestAPIFallback_WalletDeepPathAndWrongMethod pins it.
//
// /api/v1/wallets/ with no id lost the handler's own "wallet ID required" guard,
// which only existed because a prefix pattern let a request with no id reach a
// handler at all.
//
// ⚠️ A trailing slash is no longer forgiven. ServeWalletHTTP ran
// TrimSuffix(path, "/"), so /api/v1/wallets/{id}/ and
// /api/v1/wallets/{id}/members/ served the wallet and the member list. Go's mux
// does not strip a trailing slash (it only ever *adds* one, to redirect into a
// subtree pattern), so both are unmatched now. ⛔ The repo's own SDKs never send
// that shape (pkg/client/evm/wallets.go builds every path with fmt.Sprintf and
// no trailing slash), but a hand-written client that did would break.
//
// A wrong method was the handler's 405 JSON. Because "/api/v1/" matches every
// method, such a request reaches the fallback and answers 404, not 405. ⚠️ This
// is proposal §0 correction 9 arriving for real, and note it is NOT what the
// bare test mux answers: with no fallback registered the mux itself answers 405,
// so the wallet package's 405 assertions still pass while a daemon says 404.
//
// ⭐ What did *not* change, though proposal §2.3 row 2 predicted it might:
// %2F handling. A wallet id is a server-generated UUID and a member is an EVM
// address, so neither can contain a slash; and even for one that did, the old
// SplitN(path, "/", 3) kept the final segment whole, which is what
// PathValue("signerAddress") also returns. Verified: DELETE
// /api/v1/wallets/w-1/members/0x%2Fdead resolves to the member route either
// way.
//
// ⛔ Do not "fix" any of the four by adding a "/api/v1/wallets/" pattern back.
// It would shadow nothing (it is less specific than all six {id} routes) but it
// would restore the prefix's habit of answering for paths that are not wallet
// endpoints, which is the property being removed.
func (m *walletsModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) is written out at each call rather than hoisted into a
	// local: cmd/archcheck reads these registrations syntactically, and a
	// variable in the argument slot is a value it cannot resolve — the route
	// gates would silently stop seeing the wallet routes' permission.
	reg.Handle("GET /api/v1/wallets", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.ListWallets))
	reg.Handle("POST /api/v1/wallets", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.CreateWallet))
	reg.Handle("GET /api/v1/wallets/{id}", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.GetWallet))
	reg.Handle("PATCH /api/v1/wallets/{id}", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.UpdateWallet))
	reg.Handle("DELETE /api/v1/wallets/{id}", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.DeleteWallet))
	reg.Handle("GET /api/v1/wallets/{id}/members", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.ListMembers))
	reg.Handle("POST /api/v1/wallets/{id}/members", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.AddMember))
	reg.Handle("DELETE /api/v1/wallets/{id}/members/{signerAddress}", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.RemoveMember))
}
