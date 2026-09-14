package api

import (
	"fmt"
	"net/http"

	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// ⭐ 2026-09-14: hdWalletGap is GONE, and its deletion is the point of slice 2.
//
// It used to be the written reason on all four HD-wallet routes, recording that
// PermReadHDWallets and PermCreateHDWallet existed, were granted by role, and
// were referenced by no route — so any authenticated key, of any role, reached
// this whole surface. All four routes now carry a permission, so there is no
// exemption left to justify and the four lines have left
// scripts/lib/arch-baseline/ast/route-auth-exemptions.txt (16 → 12).
//
// ⛔ Do not reintroduce an AuthenticatedOnly here. The four permissions chosen,
// and why each one rather than the other, are argued on Routes() below.

// hdWalletsModule serves HD wallet creation, listing and derivation.
//
// # Why it is a module (proposal S4, copying S3's shape)
//
// A module is what lets a test drive the *production* route patterns. Routes()
// is exported and RouteRegistrar is an interface, so internal/api/handler/evm's
// external test package (package evm_test — an in-package test cannot import
// internal/api, which imports the handler package) can hand in a registrar of
// its own and get these patterns into a bare http.ServeMux. The alternative — a
// mux built in the fixture with the patterns typed in by hand — is a second
// source of truth that stays green while describing routes the daemon does not
// serve.
//
// ⚠️ Unlike walletsModule this one is handed an already-built handler rather
// than building it from repositories. That is deliberate and it is the smaller
// change: NewHDWalletHandler takes a live read-only predicate and is then fed an
// audit logger and a live per-key limit, all three read off Router state
// (router.go's liveReadOnly / liveInt and RouterConfig.AuditLogger). Moving that
// wiring into the module means moving three Router internals with it, which has
// no bearing on the route table — and this PR's whole claim is that the four
// endpoints below serve exactly what the four patterns did.
type hdWalletsModule struct {
	h *evmhandler.HDWalletHandler
}

// NewHDWalletsModule wraps a constructed HD wallet handler. It errors rather
// than registering routes that would nil-panic on the first request.
func NewHDWalletsModule(h *evmhandler.HDWalletHandler) (Module, error) {
	if h == nil {
		return nil, fmt.Errorf("hd wallet handler is required")
	}
	return &hdWalletsModule{h: h}, nil
}

func (m *hdWalletsModule) Name() string { return "hd-wallets" }

// Routes registers the HD wallet surface: four endpoints, named (proposal S4).
//
// # What changed and what did not
//
// This used to be four patterns of which only two named an endpoint:
//
//	/api/v1/evm/hd-wallets                              (any method)
//	/api/v1/evm/hd-wallets/                             (any method, any depth)
//	POST /api/v1/evm/hd-wallets/{address}/derive
//	GET  /api/v1/evm/hd-wallets/{address}/derived
//
// ⚠️ The two wildcard patterns were decorative: every one of the four went to
// HDWalletHandler.ServeHTTP, which re-derived the address by cutting r.URL.Path
// and never called PathValue. So the prefix answered for the derive/derived
// paths too whenever the method-scoped pattern did not match — GET on
// .../derive reached deriveAddresses, because the prefix matches every method.
// That is fixed by construction now: the two functions are reachable only from
// the two patterns that name them.
//
// # ⛔ Permissions: the gap is closed, one decision per route
//
// ⭐ 2026-09-14, slice 2. All four used to be AuthenticatedOnly with a written
// reason saying, in full, that this was a known RBAC gap: **any authenticated
// key of any role reached this surface**. Each now names a permission, and the
// four decisions are not the same decision:
//
//	POST /hd-wallets                  → PermCreateHDWallet  (admin only)
//	GET  /hd-wallets                  → PermReadHDWallets   (admin, dev, agent)
//	GET  /hd-wallets/{addr}/derived   → PermReadHDWallets
//	POST /hd-wallets/{addr}/derive    → PermReadHDWallets   ⚠️ see below
//
// ⭐ **create is a no-op in practice, and that is why it is the safe one.**
// hdwallet.go:228 already refuses a non-admin with 403 "admin access required",
// and PermCreateHDWallet is granted to admin alone — so the route guard and the
// handler guard now agree exactly and no caller changes behaviour. What it buys
// is that the check is no longer the *only* thing standing there: deleting the
// handler's IsAdmin() would now leave the route still closed.
//
// ⛔ derive is a WRITE on a read permission, deliberately, and it is a new row
// in route-mutating-perm.txt with that reason. The alternative was
// PermCreateHDWallet, and it is wrong here in the dangerous direction: derive's
// real check is resource-scoped — resolveAccessibleWallet runs
// accessService.CheckAccess(apiKey.ID, address) and answers 403 for a wallet
// this key may not touch — and a non-admin key legitimately derives from a
// wallet it was granted. ⚠️ Admin-only would break the extension, which is
// configured with an `agent` key (extension/background.js:4030), and it would
// break it **silently**: no test in this repo derives with a non-admin key, so
// e2e would stay green while a real caller started failing. Too strict does not
// always fail e2e — that is the asymmetry the old exemption assumed away.
//
// ⚠️ Who loses access, stated rather than buried: **`strategy`**. It holds
// neither permission, so all four endpoints are now 403 for it where all four
// used to answer. That is the grant matrix taking effect — strategy is the
// sign-only role, and rbac.go grants it read_signers but deliberately not
// read_hd_wallets. ⭐ The capability is not lost, only this route: a strategy
// key that has been granted access to an HD wallet still finds its primary
// address through GET /api/v1/evm/signers?type=hd_wallet, which is gated on
// PermReadSigners (which strategy holds) and is scoped by the same
// ownership+access set. That migration is what makes this narrowing safe rather
// than merely strict.
//
// ⚠️ One existing e2e test changed as a direct result and it is worth reading:
// TestHDWallet_NonAdminCannotList asserted that a strategy key CAN list and sees
// an empty array. Its name already said "CannotList"; the body had been relaxed
// to describe the un-gated reality. It now asserts 403, which is the stricter
// answer, not a weakened one.
//
// TestHDWalletRoutes_RegistersExactlyTheProductionPatterns asserts the pattern
// *and* its authorization for all four — none of those tests runs the middleware
// chain, so e2e's TestHDWallet_StrategyKeyIsRefusedTheWholeSurface is the
// negative verification by effect.
//
// ⚠️ Client-visible answers that changed, all of them consequences of the mux
// taking over dispatch, none avoidable without keeping a prefix pattern (which
// would keep the swallow this step exists to remove). Measured, not reasoned
// about — the "after" column is the /api/v1/ fallback's envelope,
// {"error":"not found: no such API endpoint"}:
//
//	request                                        before                    after
//	GET    /api/v1/evm/hd-wallets/                 200 the wallet list       404 JSON (fallback)
//	POST   /api/v1/evm/hd-wallets/                 201 created               404 JSON (fallback)
//	POST   /api/v1/evm/hd-wallets/{addr}/derive/   200 derived               404 JSON (fallback)
//	GET    /api/v1/evm/hd-wallets/{addr}/derived/  200 the derived list      404 JSON (fallback)
//	GET    /api/v1/evm/hd-wallets/{addr}/derive    200/400 (derive on a GET) 404 JSON (fallback)
//	GET    /api/v1/evm/hd-wallets/{addr}           404 "unknown action"      404 JSON (fallback)
//	GET    /api/v1/evm/hd-wallets/{addr}/unknown   404 "unknown action"      404 JSON (fallback)
//	GET    /api/v1/evm/hd-wallets/not-an-address   400 "invalid path…"       404 JSON (fallback)
//	PUT    /api/v1/evm/hd-wallets                  405 method not allowed    404 JSON (fallback)
//
// ⚠️ A trailing slash is no longer forgiven. ServeHTTP ran
// TrimSuffix(path, "/"), so all four shapes above with a trailing slash were
// served. Go's mux does not strip one — it only ever *adds* one, to redirect
// into a subtree pattern — so they are unmatched now. ⛔ The repo's own SDKs
// never send that shape (pkg/client/evm/hdwallet.go builds every path with
// fmt.Sprintf and no trailing slash), but a hand-written client that did would
// break.
//
// ⛔ GET .../{addr}/derive answering 200 was not a feature: the prefix pattern
// matched every method, so a GET ran a derivation (a *write*) whenever the body
// happened to parse. Losing it is the point of naming the method at the route.
//
// A wrong method on the collection was the handler's own 405 JSON. Because
// "/api/v1/" matches every method, such a request now reaches the fallback and
// answers 404. ⚠️ This is proposal §0 correction 9 arriving for real, and note
// it is NOT what the bare test mux answers: with GET and POST both registered on
// the same path and no fallback in the way, the mux itself answers 405 — so the
// package's 405 assertions still hold while a daemon says 404.
//
// ⛔ Do not "fix" any of these by adding "/api/v1/evm/hd-wallets/" back. It
// would shadow nothing, but it would restore the prefix's habit of answering for
// paths that are not HD-wallet endpoints, which is the property being removed.
func (m *hdWalletsModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) is written out at each call rather than hoisted into a
	// local: cmd/archcheck reads these registrations syntactically, and a
	// variable in the argument slot is a value it cannot resolve — the route
	// gates would silently stop seeing these four routes' permission.
	reg.Handle("GET /api/v1/evm/hd-wallets", Permitted(middleware.PermReadHDWallets), http.HandlerFunc(m.h.ListWallets))
	reg.Handle("POST /api/v1/evm/hd-wallets", Permitted(middleware.PermCreateHDWallet), http.HandlerFunc(m.h.CreateOrImport))

	// ⛔ PermReadHDWallets on a POST, on purpose — see the block above. The gate
	// that matters is resolveAccessibleWallet's per-wallet CheckAccess, which a
	// route cannot express; PermCreateHDWallet would lock out the `agent` key the
	// extension ships with, and would do it without reddening a single test.
	reg.Handle("POST /api/v1/evm/hd-wallets/{address}/derive", Permitted(middleware.PermReadHDWallets), http.HandlerFunc(m.h.Derive))
	reg.Handle("GET /api/v1/evm/hd-wallets/{address}/derived", Permitted(middleware.PermReadHDWallets), http.HandlerFunc(m.h.ListDerived))
}
