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
// # Why this is a module before the handler is decomposed (proposal S2, ahead of S3)
//
// The two patterns below used to be two r.handle calls sitting inline in
// setupRoutes. Nothing about *what* is registered changed when they moved here —
// same two literal patterns, same Permitted(PermManageWallets) on both — and
// that sameness is the point: S2 moves the wallet handler tests off direct
// h.ServeHTTP onto a real mux, and a test can only do that honestly if the
// patterns it routes through come from the production registration rather than
// from a copy written into a fixture. A copy stays green while describing routes
// the daemon does not serve, which is the exact failure the archcheck route
// gates exist to prevent.
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
// composition root like bootstrap and transactions. Finishing that means
// deleting three RouterConfig fields and wiring the module at every call site of
// NewRouter, which is S3's business, not a change to smuggle in under a test
// refactor.
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

// Routes registers the wallet surface.
//
// ⛔ Two patterns, eight endpoints: ServeWalletHTTP still splits r.URL.Path into
// {id}, /members and /members/{signerAddress} itself, and the
// handler-path-dispatch baseline records it. Decomposing that — one route per
// method and sub-path, r.PathValue instead of SplitN — is S3. Adding or
// reshaping a pattern here is therefore a behaviour change, not a tidy-up.
func (m *walletsModule) Routes(reg RouteRegistrar) {
	reg.Handle("/api/v1/wallets", Permitted(middleware.PermManageWallets), m.h)
	reg.Handle("/api/v1/wallets/", Permitted(middleware.PermManageWallets), http.HandlerFunc(m.h.ServeWalletHTTP))
}
