package api

import (
	"fmt"
	"net/http"

	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
)

// hdWalletGap is the written reason on all four HD-wallet routes, and it is the
// exemption itself rather than a comment about one — route_auth.go's
// AuthenticatedOnly refuses an empty one, and scripts/lib/arch-baseline/ast/
// route-auth-exemptions.txt ratchets every line that carries it.
//
// ⛔ It is reproduced here byte for byte from where it stood in router.go before
// S4. Decomposing a route may not change what it declares about authorization,
// and this string is what these four declare.
//
// ⛔ Do NOT "fix" the gap while decomposing. PermReadHDWallets and
// PermCreateHDWallet exist and are granted by role, and assigning them here
// would look like tidying up. It is a security decision with an asymmetric
// failure direction — too strict fails e2e, too loose ships silently — and it
// belongs to its own PR, argued on its own. Proposal §2.5 records "the
// decomposition quietly changed a permission" as the single semantically
// irreversible risk in this plan.
const hdWalletGap = "⛔ KNOWN GAP, not a decision: PermReadHDWallets/PermCreateHDWallet exist and are granted by role, " +
	"but no HD-wallet route references them, so any authenticated key reaches this surface. " +
	"Left as-is here because assigning the permission is a security decision that has to be made per route, " +
	"and a too-loose guess would ship silently while a too-strict one would fail e2e."

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
// ⛔ Every one of the four is AuthenticatedOnly(hdWalletGap), byte for byte what
// the four patterns declared. See hdWalletGap: the permission gap is real, known,
// and deliberately not closed here.
// TestHDWalletRoutes_RegistersExactlyTheProductionPatterns asserts the pattern
// *and* its authorization for all four, and is the only thing in the HD-wallet
// family that would notice a change here — none of those tests runs the
// middleware chain.
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
	// ⚠️ AuthenticatedOnly(hdWalletGap) is written out at each call rather than
	// hoisted into a per-call local: cmd/archcheck reads these registrations
	// syntactically. A package-level const it can resolve; a local variable in
	// the argument slot it cannot, and the exemption gate would silently stop
	// seeing these four routes.
	reg.Handle("GET /api/v1/evm/hd-wallets", AuthenticatedOnly(hdWalletGap), http.HandlerFunc(m.h.ListWallets))
	reg.Handle("POST /api/v1/evm/hd-wallets", AuthenticatedOnly(hdWalletGap), http.HandlerFunc(m.h.CreateOrImport))
	reg.Handle("POST /api/v1/evm/hd-wallets/{address}/derive", AuthenticatedOnly(hdWalletGap), http.HandlerFunc(m.h.Derive))
	reg.Handle("GET /api/v1/evm/hd-wallets/{address}/derived", AuthenticatedOnly(hdWalletGap), http.HandlerFunc(m.h.ListDerived))
}
