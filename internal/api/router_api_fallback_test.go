package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------- the /api/v1/ JSON-404 net (proposal §2.3 row 1, step S1②) ----------
//
// ⚠️ What these tests can and cannot reach, said up front so the names are not
// read as promising more than they check.
//
// setupRoutes cannot run in this layer: it builds a SignHandler, which requires
// a live *service.SignService and a SignerAccessService, which require repos and
// a database. So the registration under test is reached through
// registerAPIFallback — the *production* function, holding the production
// pattern, RouteAuth and handler — rather than through a copy of its arguments
// written into a fixture. The sibling patterns each test registers alongside it
// ARE copies of what setupRoutes registers, and what they prove is a property of
// http.ServeMux's precedence given those patterns, not that setupRoutes still
// contains them. Proving the latter needs the maximal-config router test, which
// is item ③ of the same step and is not here yet.
//
// ⛔ Nothing below asserts a permission or an auth mode as *correct*; they are
// asserted only as *unchanged*, which is the property a refactor owes.

// ⚠️ Named for this file rather than shared: a package-level testLogger already
// exists in router_maximal_config_test.go, and two test files reaching for one
// helper name is how a merge conflict turns into a compile error.
func fallbackTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newChainedTestRouter is newTestRouter plus the two fields the authenticated
// middleware chain dereferences. Still no database, no verifier: an
// unauthenticated request is refused by AuthMiddleware before either is read.
func newChainedTestRouter() *Router {
	lg := fallbackTestLogger()
	return &Router{
		mux:         http.NewServeMux(),
		routeAuth:   map[string]RouteAuth{},
		rateLimiter: middleware.NewRateLimiter(lg),
		logger:      lg,
	}
}

// TestAPIFallback_DoesNotShadowRegisteredRoutes is the "prove it shadows
// nothing" half. It asks the mux the same question Router.Handler asks on every
// request — which pattern would you dispatch this to? — with the fallback
// registered alongside patterns copied from setupRoutes.
//
// ⚠️ The paths that must NOT reach the fallback are the interesting rows: a
// prefix route, a method-scoped literal, a wildcard route, and the four signer
// actions this same change expanded out of a loop.
func TestAPIFallback_DoesNotShadowRegisteredRoutes(t *testing.T) {
	r := newChainedTestRouter()

	// Copies of live registrations (router.go), one of each shape.
	r.handle("POST /api/v1/evm/sign", Public("test fixture"), okHandler("sign"))
	r.handle("/api/v1/evm/rules", Public("test fixture"), okHandler("rules"))
	r.handle("/api/v1/evm/rules/", Public("test fixture"), okHandler("rules-prefix"))
	r.handle("POST /api/v1/evm/rules/{id}/budgets/reset", Public("test fixture"), okHandler("budget-reset"))
	r.handle("GET /api/v1/evm/signers", Public("test fixture"), okHandler("signers"))
	r.handle("POST /api/v1/evm/signers/{address}/unlock", Public("test fixture"), okHandler("unlock"))
	r.handle("POST /api/v1/evm/signers/{address}/transfer", Public("test fixture"), okHandler("transfer"))
	// ⚠️ This used to be `/api/v1/evm/signers/` — the method-less prefix that
	// carried five endpoints and matched every verb. S4's last third replaced it
	// with named routes; the access sub-tree is the shape worth keeping here,
	// because it is the one that answers three different methods on one path.
	r.handle("GET /api/v1/evm/signers/{address}/access", Public("test fixture"), okHandler("access-list"))
	r.handle("GET /health", Public("test fixture"), okHandler("health"))
	// ⛔ The two routes with the most to lose from being shadowed. They are the
	// only Public patterns under /api/v1 (module_bootstrap.go), and they are what
	// a daemon with no API key yet talks to — an operator bringing up a fresh
	// install has nothing to authenticate with. If the AuthenticatedOnly fallback
	// ever swallowed them, first-run bootstrap would answer 401 to a caller who
	// cannot possibly satisfy it, and the daemon would be unbootstrappable.
	r.handle("GET /api/v1/bootstrap/status", Public("test fixture"), okHandler("bootstrap-status"))
	r.handle("POST /api/v1/bootstrap/admin", Public("test fixture"), okHandler("bootstrap-admin"))
	r.handle("/", PublicUnwrapped("test fixture"), okHandler("spa"))

	// The production registration. If this panicked — the pattern-conflict shape
	// of proposal §2.2 — the test would fail here, at NewRouter's equivalent.
	r.registerAPIFallback()

	for _, tc := range []struct {
		name   string
		method string
		target string
		want   string
	}{
		{"literal method-scoped route", http.MethodPost, "/api/v1/evm/sign", "POST /api/v1/evm/sign"},
		{"collection route", http.MethodGet, "/api/v1/evm/rules", "/api/v1/evm/rules"},
		{"prefix route keeps deep paths", http.MethodGet, "/api/v1/evm/rules/a/b/c/d", "/api/v1/evm/rules/"},
		{"prefix route keeps one segment", http.MethodGet, "/api/v1/evm/rules/rule-1", "/api/v1/evm/rules/"},
		{"wildcard sub-path", http.MethodPost, "/api/v1/evm/rules/rule-1/budgets/reset", "POST /api/v1/evm/rules/{id}/budgets/reset"},
		{"signer collection", http.MethodGet, "/api/v1/evm/signers", "GET /api/v1/evm/signers"},
		{"signer action unlock", http.MethodPost, "/api/v1/evm/signers/0xabc/unlock", "POST /api/v1/evm/signers/{address}/unlock"},
		{"signer action transfer", http.MethodPost, "/api/v1/evm/signers/0xabc/transfer", "POST /api/v1/evm/signers/{address}/transfer"},
		{"signer access, now its own route", http.MethodGet, "/api/v1/evm/signers/0xabc/access", "GET /api/v1/evm/signers/{address}/access"},
		{"non-API route is untouched", http.MethodGet, "/health", "GET /health"},
		// ⛔ Unauthenticated bootstrap must keep reaching its own handler. These
		// are the highest-consequence rows in the table: a caller doing first-run
		// setup has no key, so a 401 here is not a stricter answer, it is a dead
		// end. Public under an AuthenticatedOnly namespace is exactly the pairing
		// that would break quietly — the mux resolves by specificity, so it holds,
		// but "it holds" is a property worth a test rather than a reading of the
		// precedence rules.
		{"bootstrap status stays public", http.MethodGet, "/api/v1/bootstrap/status", "GET /api/v1/bootstrap/status"},
		{"bootstrap admin stays public", http.MethodPost, "/api/v1/bootstrap/admin", "POST /api/v1/bootstrap/admin"},
		{"SPA still owns everything outside /api/v1", http.MethodGet, "/dashboard/rules", "/"},

		// ⭐ The rows the net exists for: paths under /api/v1 that no pattern
		// claims. Before this change every one of them landed on "/".
		{"unknown API path", http.MethodGet, "/api/v1/nope", "/api/v1/"},
		{"unknown API sub-tree", http.MethodGet, "/api/v1/evm/does-not-exist/deep/path", "/api/v1/"},
		{"decomposed rules deep path", http.MethodDelete, "/api/v1/evm/rulez/a/b/c/d", "/api/v1/"},
		{"the namespace root itself", http.MethodGet, "/api/v1/", "/api/v1/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pattern := r.mux.Handler(httptest.NewRequest(tc.method, tc.target, nil))
			if pattern != tc.want {
				t.Fatalf("%s %s dispatches to %q, want %q", tc.method, tc.target, pattern, tc.want)
			}
		})
	}
}

// TestAPIFallback_ReplacesTheSPAsHTMLForAPIPaths is the negative half, run in
// both directions in one test: the same request against a router without the
// fallback and with it. Without it the API client receives the SPA's HTML;
// with it, it does not.
//
// ⚠️ The status differs between the two arms for a second reason, and it is the
// point of AuthenticatedOnly: the request carries no credential, so the chain
// stops at 401 rather than reaching the 404 body. Either way the answer is no
// longer HTML, which is what a JSON client breaks on. The 404 body itself is
// pinned by TestAPIFallback_BodyIsTheStandardErrorEnvelope.
func TestAPIFallback_ReplacesTheSPAsHTMLForAPIPaths(t *testing.T) {
	const spaBody = "<!doctype html><html><body>remote-signer web ui</body></html>"

	withSPA := func() *Router {
		r := newChainedTestRouter()
		r.handle("POST /api/v1/evm/sign", Public("test fixture"), okHandler("sign"))
		r.handle("/", PublicUnwrapped("test fixture"), okHandler(spaBody))
		return r
	}

	req := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules/a/b/c/d", nil)
	}

	// Before: the catch-all answers, with HTML, at 200.
	before := httptest.NewRecorder()
	withSPA().Handler().ServeHTTP(before, req())
	if before.Code != http.StatusOK || !strings.Contains(before.Body.String(), "<html") {
		t.Fatalf("baseline arm answered %d %q — this test's premise (the SPA swallows unmatched API paths) no longer holds",
			before.Code, before.Body.String())
	}

	// After: same request, same router plus the fallback.
	r := withSPA()
	r.registerAPIFallback()
	after := httptest.NewRecorder()
	r.Handler().ServeHTTP(after, req())

	if strings.Contains(after.Body.String(), "<html") || strings.Contains(after.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("an unmatched API path still answers HTML: %d %q content-type=%q",
			after.Code, after.Body.String(), after.Header().Get("Content-Type"))
	}
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request to an unmatched API path answered %d, want 401 — "+
			"the fallback is AuthenticatedOnly, so the chain must refuse before the 404 body", after.Code)
	}
}

// TestAPIFallback_BodyIsTheStandardErrorEnvelope pins the shape a client
// parses: respond.Error's {"error": ...} under application/json, the same
// envelope the 83 other JSON writes in this API use. ⛔ A second shape here
// would mean a client needs a second parser for the one response it did not
// ask for.
func TestAPIFallback_BodyIsTheStandardErrorEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	newChainedTestRouter().apiNotFound(rec, httptest.NewRequest(http.MethodGet, "/api/v1/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	if len(body) != 1 || body["error"] == "" {
		t.Fatalf("body = %v, want exactly one key \"error\" with a message", body)
	}
	// ⛔ The path must not be reflected back; see the note on apiNotFound.
	if strings.Contains(body["error"], "nope") {
		t.Fatalf("the 404 message echoes the requested path: %q", body["error"])
	}
}

// TestAPIFallback_WalletDeepPathAndWrongMethod is the net being cashed in.
//
// ⭐ Everything above was written *before* any handler was decomposed, so it
// proved the fallback catches paths a decomposition *would* strand. Wallet is
// the first one decomposed (proposal S3), so this is the first test where the
// stranded paths are real rather than hypothetical: "/api/v1/wallets/a/b/c/d"
// and "/api/v1/wallets/" were both swallowed by the "/api/v1/wallets/" prefix
// pattern and answered by WalletHandler; no wallet pattern claims them now.
//
// ⛔ The patterns come from walletsModule.Routes(), never from literals here. A
// literal list would be a second route table that stays green while describing
// routes the daemon does not serve — and this test's entire subject is which
// paths the daemon's own patterns leave over.
//
// ⚠️ What each half checks, and why they are different questions:
//
//   - dispatch: which pattern the mux resolves each path to. Exact, and the only
//     way to say "this path reaches the fallback and not a wallet route".
//   - the answer: unauthenticated, so the AuthenticatedOnly fallback stops at
//     401. That is fine and is the point — what matters to a JSON client is that
//     it is no longer the SPA's text/html 200. The 404 body itself is
//     TestAPIFallback_BodyIsTheStandardErrorEnvelope's subject.
func TestAPIFallback_WalletDeepPathAndWrongMethod(t *testing.T) {
	walletsMod, err := NewWalletsModule(&stubWalletRepo{}, &stubSignerOwnershipRepo{}, &stubSignerAccessRepo{}, fallbackTestLogger())
	if err != nil {
		t.Fatalf("building the wallets module: %v", err)
	}

	// Collect the real patterns so the "still reaches its own route" rows below
	// are generated rather than restated.
	var walletPatterns []string
	walletsMod.Routes(patternCollector(func(pattern string, _ RouteAuth) {
		walletPatterns = append(walletPatterns, pattern)
	}))
	if len(walletPatterns) == 0 {
		t.Fatal("walletsModule registered nothing, so every row below would pass for the wrong reason")
	}

	r := newChainedTestRouter()
	r.mountModules(walletsMod)
	r.handle("/", PublicUnwrapped("test fixture"), okHandler("<!doctype html><html>spa</html>"))
	r.registerAPIFallback()

	// Each real endpoint still resolves to its own pattern: the fallback added
	// nothing that shadows them, and the decomposition left none of them behind.
	for _, pattern := range walletPatterns {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Fatalf("wallet pattern %q has no method — the rows below assume method+path patterns", pattern)
		}
		// Substitute a value for each wildcard segment.
		target := strings.NewReplacer("{id}", "w-1", "{signerAddress}", "0xdead").Replace(path)
		if strings.Contains(target, "{") {
			t.Fatalf("wallet pattern %q has a wildcard this test does not know how to fill: %q", pattern, target)
		}
		if _, got := r.mux.Handler(httptest.NewRequest(method, target, nil)); got != pattern {
			t.Errorf("%s %s dispatches to %q, want its own route %q", method, target, got, pattern)
		}
	}

	// ⭐ And the paths the decomposition stranded reach the fallback, not a
	// wallet route and not the SPA.
	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{"deep path the prefix used to swallow", http.MethodGet, "/api/v1/wallets/a/b/c/d"},
		{"the bare prefix, which answered 400 before", http.MethodGet, "/api/v1/wallets/"},
		{"an unknown sub-resource", http.MethodGet, "/api/v1/wallets/w-1/unknown"},
		// ⚠️ A trailing slash used to be forgiven by ServeWalletHTTP's
		// TrimSuffix and served the wallet; Go's mux never strips one, so these
		// are unmatched now. Listed as rows rather than left to be discovered by
		// whoever wrote the client that sends them.
		{"a wallet with a trailing slash", http.MethodGet, "/api/v1/wallets/w-1/"},
		{"members with a trailing slash", http.MethodGet, "/api/v1/wallets/w-1/members/"},
		// ⚠️ Proposal §0 correction 9, arriving for real: the mux answers 405
		// only when *nothing* matches, and "/api/v1/" matches every method. So a
		// wrong method under /api/v1 is a 404, not a 405. Before S3 this one was
		// WalletHandler's own 405 JSON.
		{"a method no wallet route serves", http.MethodDelete, "/api/v1/wallets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pattern := r.mux.Handler(httptest.NewRequest(tc.method, tc.target, nil))
			if pattern != "/api/v1/" {
				t.Fatalf("%s %s dispatches to %q, want the /api/v1/ fallback — "+
					"a wallet pattern is still claiming more than one endpoint's worth of paths",
					tc.method, tc.target, pattern)
			}

			rec := httptest.NewRecorder()
			r.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if strings.Contains(rec.Body.String(), "<html") || strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s answered HTML (%d, content-type %q) — a JSON client would break on it",
					tc.method, tc.target, rec.Code, rec.Header().Get("Content-Type"))
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s answered %d, want 401: the request carries no credential and the fallback is "+
					"AuthenticatedOnly, so the chain must refuse before the 404 body", tc.method, tc.target, rec.Code)
			}
		})
	}
}

// TestAPIFallback_SignerStrandedPaths is where the behaviour-change table on
// signersModule.Routes is *measured* rather than reasoned about, and it is the
// highest-consequence one of the three: the pattern being removed,
// "/api/v1/evm/signers/", was registered with no method, so it matched every
// verb — and until 6d30ba1 that meant `GET .../{address}/unlock` unlocked a
// signer and `DELETE .../{address}/approve` approved one.
//
// ⚠️ The handler-package tests for this module run against a bare mux with no
// fallback, so they see the mux's own 404 and 405. Here the real
// registerAPIFallback stands next to the real module, which is the only place
// the daemon's answer is visible: "/api/v1/" matches every path and every
// method, so ⛔ the daemon never answers 405 for these — every stranded shape,
// wrong-verb ones included, lands on the JSON 404 fallback. What must never
// happen is that it lands on the SPA and comes back text/html to a JSON client.
func TestAPIFallback_SignerStrandedPaths(t *testing.T) {
	signersMod, err := NewSignersModule(maximalSignerHandler(t))
	if err != nil {
		t.Fatalf("building the signers module: %v", err)
	}

	var patterns []string
	signersMod.Routes(patternCollector(func(pattern string, _ RouteAuth) {
		patterns = append(patterns, pattern)
	}))
	if len(patterns) != 11 {
		t.Fatalf("signersModule registered %d patterns, want 11 — the rows below would pass for the wrong reason",
			len(patterns))
	}

	r := newChainedTestRouter()
	r.mountModules(signersMod)
	r.handle("/", PublicUnwrapped("test fixture"), okHandler("<!doctype html><html>spa</html>"))
	r.registerAPIFallback()

	const addr = "0x1111111111111111111111111111111111111111"

	// Each real endpoint still resolves to its own pattern: the fallback shadows
	// none of them, and the decomposition left none of them behind.
	for _, pattern := range patterns {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Fatalf("signer pattern %q has no method — the rows below assume method+path patterns", pattern)
		}
		target := strings.NewReplacer("{address}", addr, "{keyID}", "k-1").Replace(path)
		if strings.Contains(target, "{") {
			t.Fatalf("signer pattern %q has a wildcard this test does not know how to fill: %q", pattern, target)
		}
		if _, got := r.mux.Handler(httptest.NewRequest(method, target, nil)); got != pattern {
			t.Errorf("%s %s dispatches to %q, want its own route %q", method, target, got, pattern)
		}
	}

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		// ⛔ The four rows this whole step exists for. Every one of them reached
		// HandleSignerAction through the method-less prefix and performed the
		// action — until 6d30ba1 put a guard inside the handler and made them
		// answer 405 instead. There is now no handler for them to reach at all,
		// which is the difference between a rule someone remembered to write and
		// a rule the router cannot forget.
		{"GET on unlock, which used to unlock the signer", http.MethodGet, "/api/v1/evm/signers/" + addr + "/unlock"},
		{"GET on lock, which used to lock it", http.MethodGet, "/api/v1/evm/signers/" + addr + "/lock"},
		{"DELETE on approve, which used to approve it", http.MethodDelete, "/api/v1/evm/signers/" + addr + "/approve"},
		{"PATCH on transfer, which used to transfer ownership", http.MethodPatch, "/api/v1/evm/signers/" + addr + "/transfer"},
		// ---- what else the prefix used to swallow (measured, see module_signers.go) ----
		{"the bare prefix, which answered 400 invalid path", http.MethodGet, "/api/v1/evm/signers/"},
		{"an unknown action, which answered 400 unknown action", http.MethodPost, "/api/v1/evm/signers/" + addr + "/foobar"},
		{"a signer with no action, which answered 400 invalid path", http.MethodGet, "/api/v1/evm/signers/" + addr},
		{"revoke with no key id, which answered 400 api_key_id is required", http.MethodDelete, "/api/v1/evm/signers/" + addr + "/access"},
		// ⚠️ Not a 404 before: SplitN(path, "/", 3) put "k-1/extra" in the third
		// part and handleAccess's GET branch ignored it, so a path two segments
		// deeper than any endpoint returned the signer's access list, 200.
		{"deeper than any endpoint, which returned the access list", http.MethodGet, "/api/v1/evm/signers/" + addr + "/access/k-1/extra"},
		// ⚠️ Trailing slash. Unlike the HD wallet handler, signer.go never ran
		// TrimSuffix(path, "/") — the empty last segment simply became an empty
		// *action*, and the action-less branch runs for DELETE and PATCH. So these
		// two rows are a real 204-and-deleted and 200-and-patched being withdrawn,
		// not a forgiving alias.
		{"a signer with a trailing slash, which DELETE used to honour", http.MethodDelete, "/api/v1/evm/signers/" + addr + "/"},
		{"a signer with a trailing slash, which PATCH used to honour", http.MethodPatch, "/api/v1/evm/signers/" + addr + "/"},
		// ⚠️ This one was a 301, not a 405: ServeMux redirects a path with no
		// match to the subtree pattern one level up, and "/api/v1/evm/signers/"
		// was such a pattern, so PUT on the collection was bounced into the prefix
		// and answered 400 there. With the prefix gone there is nothing to
		// redirect to, and proposal §0 correction 9 applies — "/api/v1/" matches
		// every method, so it is a 404 rather than a 405.
		{"a method the collection does not serve, which used to 301 into the prefix", http.MethodPut, "/api/v1/evm/signers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pattern := r.mux.Handler(httptest.NewRequest(tc.method, tc.target, nil))
			if pattern != "/api/v1/" {
				t.Fatalf("%s %s dispatches to %q, want the /api/v1/ fallback — "+
					"a signer pattern is still claiming more than one endpoint's worth of paths",
					tc.method, tc.target, pattern)
			}

			rec := httptest.NewRecorder()
			r.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if strings.Contains(rec.Body.String(), "<html") || strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s answered HTML (%d, content-type %q) — a JSON client would break on it",
					tc.method, tc.target, rec.Code, rec.Header().Get("Content-Type"))
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s answered %d, want 401: the request carries no credential and the fallback is "+
					"AuthenticatedOnly, so the chain must refuse before the 404 body", tc.method, tc.target, rec.Code)
			}
		})
	}
}

// TestAPIFallback_RulesPrefixStillAnswersItsOwn400 is the one the task calls
// for by name, and it runs the real handler/evm/rule.go — not a marker — behind
// the real patterns, with the fallback registered.
//
// ⚠️ Registered as Public here purely so the request reaches the handler without
// a signed API key; the live registration is Permitted(PermListRules) and this
// test says nothing about that. What it pins is that a deep path still reaches
// RuleHandler and still comes back 400 JSON, and that a real endpoint next to it
// still reaches its handler and answers 200.
func TestAPIFallback_RulesPrefixStillAnswersItsOwn400(t *testing.T) {
	ruleHandler, err := evmhandler.NewRuleHandler(storage.NewMemoryRuleRepository(), fallbackTestLogger())
	if err != nil {
		t.Fatalf("building the real rule handler: %v", err)
	}

	r := newChainedTestRouter()
	r.handle("/api/v1/evm/rules", Public("test fixture"), ruleHandler)
	r.handle("/api/v1/evm/rules/", Public("test fixture"), ruleHandler)
	r.handle("/", PublicUnwrapped("test fixture"), okHandler("<html>spa</html>"))
	r.registerAPIFallback()

	admin := &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
	do := func(method, target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, admin))
		rec := httptest.NewRecorder()
		r.Handler().ServeHTTP(rec, req)
		return rec
	}

	// ⭐ The behaviour proposal §2.3 row 1 says must not change.
	deep := do(http.MethodGet, "/api/v1/evm/rules/a/b/c/d")
	if deep.Code != http.StatusBadRequest {
		t.Fatalf("deep rules path answered %d %q, want 400 from rule.go — the fallback shadowed the prefix route",
			deep.Code, deep.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(deep.Body.Bytes(), &body); err != nil {
		t.Fatalf("deep rules path body %q is not JSON: %v", deep.Body.String(), err)
	}
	if body["error"] != "invalid rule_id format" {
		t.Fatalf("deep rules path said %q, want rule.go's own \"invalid rule_id format\"", body["error"])
	}

	// A known real endpoint still reaches its handler through the same mux.
	list := do(http.MethodGet, "/api/v1/evm/rules")
	if list.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/evm/rules answered %d %q, want 200", list.Code, list.Body.String())
	}
}

// TestAPIFallback_SettingsStrandedPaths is where the behaviour-change table on
// settingsModule.Routes is *measured* rather than reasoned about.
//
// ⚠️ Unlike the three modules before it, this one closes no reachability defect:
// SettingsHandler.ServeHTTP dispatched on `switch r.Method` with a 405 default
// and rejected every deep path with 400, so nothing here ever mutated on a read
// verb and nothing ever leaked a snapshot from a path no endpoint owned. What it
// closes is the *schema* hole — the request body type varied with a path segment
// — and the stranded shapes below are the price of removing the prefix that
// allowed that.
//
// ⚠️ The handler-package tests for this module run against a bare mux with no
// fallback, so they see the mux's own 404 and 405. Here the real
// registerAPIFallback stands next to the real module, which is the only place
// the daemon's answer is visible: "/api/v1/" matches every path and every
// method, so ⛔ the daemon never answers 405 for these — every stranded shape,
// wrong-verb ones included, lands on the JSON 404 fallback. What must never
// happen is that it lands on the SPA and comes back text/html to a JSON client.
func TestAPIFallback_SettingsStrandedPaths(t *testing.T) {
	settingsMod, err := NewSettingsModule(maximalSettingsHandler(t))
	if err != nil {
		t.Fatalf("building the settings module: %v", err)
	}

	var patterns []string
	settingsMod.Routes(patternCollector(func(pattern string, _ RouteAuth) {
		patterns = append(patterns, pattern)
	}))
	if len(patterns) != 18 {
		t.Fatalf("settingsModule registered %d patterns, want 18 — the rows below would pass for the wrong reason",
			len(patterns))
	}

	r := newChainedTestRouter()
	r.mountModules(settingsMod)
	r.handle("/", PublicUnwrapped("test fixture"), okHandler("<!doctype html><html>spa</html>"))
	r.registerAPIFallback()

	// Each real endpoint still resolves to its own pattern: the fallback shadows
	// none of them, and the decomposition left none of them behind. ⚠️ The group
	// segments contain dots; this is where "a dot is an ordinary character in a
	// mux path segment" is measured rather than assumed.
	for _, pattern := range patterns {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Fatalf("settings pattern %q has no method — the rows below assume method+path patterns", pattern)
		}
		if strings.Contains(path, "{") {
			t.Fatalf("settings pattern %q has a wildcard — ⛔ S5's whole point is that the group is a "+
				"literal segment, so that each route carries one concrete body type", pattern)
		}
		if _, got := r.mux.Handler(httptest.NewRequest(method, path, nil)); got != pattern {
			t.Errorf("%s %s dispatches to %q, want its own route %q", method, path, got, pattern)
		}
	}

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		// ---- what the prefix used to swallow, all of them 400 or 405 before ----
		{"the bare prefix, which answered 400 group required", http.MethodGet, "/api/v1/admin/settings/"},
		{"the bare prefix on a PUT", http.MethodPut, "/api/v1/admin/settings/"},
		// ⚠️ Trailing slash, and in the direction opposite to hd-wallets: settings
		// never ran TrimSuffix, so "security/" hit the slash guard and answered
		// 400. It was already refused; only the status and body change.
		{"a group with a trailing slash", http.MethodGet, "/api/v1/admin/settings/security/"},
		{"a group with a trailing slash on a PUT", http.MethodPut, "/api/v1/admin/settings/security/"},
		{"a deep path, which answered 400 group required", http.MethodGet, "/api/v1/admin/settings/security/extra"},
		{"a deeper path still", http.MethodGet, "/api/v1/admin/settings/a/b/c/d"},
		{"an unknown group, which answered 404 unknown settings group", http.MethodGet, "/api/v1/admin/settings/unknown.group"},
		{"an unknown group on a PUT, which answered 400", http.MethodPut, "/api/v1/admin/settings/unknown.group"},
		// ⚠️ These three were the handler's own 405. ⛔ They never mutated —
		// settings had no verb hole — so this row is a status change, not a
		// defect being closed.
		{"POST on a group, which answered 405", http.MethodPost, "/api/v1/admin/settings/security"},
		{"DELETE on a group, which answered 405", http.MethodDelete, "/api/v1/admin/settings/security"},
		{"PATCH on a group, which answered 405", http.MethodPatch, "/api/v1/admin/settings/security"},
		// ⚠️ These two were **301 redirects**, not 405s: ServeMux redirects a path
		// with no match to the subtree pattern one level up, and
		// "/api/v1/admin/settings/" was such a pattern, so the collection — on any
		// verb — was bounced into the prefix and answered 400 there. With the
		// prefix gone there is nothing to redirect to.
		{"the collection, which used to 301 into the prefix", http.MethodGet, "/api/v1/admin/settings"},
		{"the collection on a PUT, which used to 301 into the prefix", http.MethodPut, "/api/v1/admin/settings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pattern := r.mux.Handler(httptest.NewRequest(tc.method, tc.target, nil))
			if pattern != "/api/v1/" {
				t.Fatalf("%s %s dispatches to %q, want the /api/v1/ fallback — "+
					"a settings pattern is still claiming more than one endpoint's worth of paths",
					tc.method, tc.target, pattern)
			}

			rec := httptest.NewRecorder()
			r.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if strings.Contains(rec.Body.String(), "<html") || strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s answered HTML (%d, content-type %q) — a JSON client would break on it",
					tc.method, tc.target, rec.Code, rec.Header().Get("Content-Type"))
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s answered %d, want 401: the request carries no credential and the fallback is "+
					"AuthenticatedOnly, so the chain must refuse before the 404 body", tc.method, tc.target, rec.Code)
			}
		})
	}
}

// TestAPIFallback_TemplateStrandedPaths is where the behaviour-change table on
// templatesModule.Routes is *measured* rather than reasoned about, and it is the
// only one of the six where a shape being stranded is a call some client really
// makes rather than a shape nobody sends.
//
// ⛔ The first three rows are the point of the whole step. Until the clients
// changed, "/api/v1/templates/evm/erc20" was a working call — measured on the
// old handler: 200 with the template, because ServeHTTP took the entire
// remainder of the path as an id and a suffix ladder told "template evm/erc20"
// apart from "template evm, sub-action erc20". That ambiguity is what no route
// table can express. Every in-repo client now percent-encodes; a published npm
// remote-signer-client 0.0.5 does not and lands here.
//
// ⚠️ Unlike presets, signers and hd-wallets, none of these rows closes a verb
// hole. ServeHTTP checked the method before every mutation — all three of its
// branches had a 405 default — so the wrong-verb rows below were already refused
// and are status changes, not defects. What is closed is the ambiguity and the
// depth swallow (POST /api/v1/templates/a/b/c/instantiate reached
// instantiateTemplate with templateID "a/b/c").
//
// ⚠️ The handler-package tests for this module run against a bare mux with no
// fallback, so they see the mux's own 404 and 405. Here the real
// registerAPIFallback stands next to the real module, which is the only place
// the daemon's answer is visible: "/api/v1/" matches every path and every
// method, so ⛔ the daemon never answers 405 for these — every stranded shape,
// wrong-verb ones included, lands on the JSON 404 fallback. What must never
// happen is that it lands on the SPA and comes back text/html to a JSON client.
func TestAPIFallback_TemplateStrandedPaths(t *testing.T) {
	templatesMod, err := NewTemplatesModule(maximalTemplateHandler(t))
	if err != nil {
		t.Fatalf("building the templates module: %v", err)
	}

	var patterns []string
	templatesMod.Routes(patternCollector(func(pattern string, _ RouteAuth) {
		patterns = append(patterns, pattern)
	}))
	if len(patterns) != 8 {
		t.Fatalf("templatesModule registered %d patterns, want 8 — the rows below would pass for the wrong reason",
			len(patterns))
	}

	r := newChainedTestRouter()
	r.mountModules(templatesMod)
	r.handle("/", PublicUnwrapped("test fixture"), okHandler("<!doctype html><html>spa</html>"))
	r.registerAPIFallback()

	// ⭐ The encoded form of a shipped registry id. This is the string that has to
	// keep resolving to its own route, and it is the reason the id sub-tree could
	// be named at all.
	const encodedID = "evm%2Ferc20"

	// Each real endpoint still resolves to its own pattern: the fallback shadows
	// none of them, and the decomposition left none of them behind.
	for _, pattern := range patterns {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Fatalf("template pattern %q has no method — the rows below assume method+path patterns", pattern)
		}
		target := strings.NewReplacer("{id}", encodedID, "{ruleID}", "inst_0123456789abcdef").Replace(path)
		if strings.Contains(target, "{") {
			t.Fatalf("template pattern %q has a wildcard this test does not know how to fill: %q", pattern, target)
		}
		if _, got := r.mux.Handler(httptest.NewRequest(method, target, nil)); got != pattern {
			t.Errorf("%s %s dispatches to %q, want its own route %q", method, target, got, pattern)
		}
	}

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		// ⛔ The three rows this whole step exists for: an unencoded id was a
		// working call and is not one any more.
		{"an unencoded id, which returned the template", http.MethodGet, "/api/v1/templates/evm/erc20"},
		{"an unencoded id on instantiate, which instantiated", http.MethodPost, "/api/v1/templates/evm/erc20/instantiate"},
		{"an unencoded id on validate, which validated", http.MethodPost, "/api/v1/templates/evm/agent/validate"},
		// ---- what the two prefixes used to swallow (measured, see module_templates.go) ----
		// ⚠️ Trailing slash in the *forgiving* direction: TrimPrefix twice left the
		// empty string, so "/api/v1/templates/" WAS the collection — a GET listed
		// and a POST created a template.
		{"the collection with a trailing slash, which listed", http.MethodGet, "/api/v1/templates/"},
		{"the collection with a trailing slash, which created", http.MethodPost, "/api/v1/templates/"},
		{"an item with a trailing slash, which answered 404 template not found", http.MethodGet, "/api/v1/templates/" + encodedID + "/"},
		{"instantiate with a trailing slash, which answered 405", http.MethodPost, "/api/v1/templates/" + encodedID + "/instantiate/"},
		{"validate with a trailing slash, which answered 405", http.MethodPost, "/api/v1/templates/" + encodedID + "/validate/"},
		// ⚠️ The depth swallow, and the only row here that was a real defect:
		// TrimPrefix + TrimSuffix accepted any depth, so this reached
		// instantiateTemplate with templateID "a/b/c".
		{"instantiate three segments deep, which ran on \"a/b/c\"", http.MethodPost, "/api/v1/templates/a/b/c/instantiate"},
		{"a deep path, which answered 404 template not found", http.MethodGet, "/api/v1/templates/a/b/c/d"},
		{"an unknown sub-action, which answered 404 template not found", http.MethodGet, "/api/v1/templates/" + encodedID + "/unknown"},
		// ⚠️ This one read as a template whose id was "instances/{id}", so it
		// answered "template not found" — a message about the wrong resource.
		{"an instance with no revoke suffix", http.MethodGet, "/api/v1/templates/instances/inst_0123456789abcdef"},
		// ---- verbs no route declares; all of these were the handler's own 405 ----
		// ⛔ Stated as status changes, not as a hole being closed: every one of
		// them was already refused before it could mutate anything.
		{"PUT on the collection, which answered 405", http.MethodPut, "/api/v1/templates"},
		{"POST on an item, which answered 405", http.MethodPost, "/api/v1/templates/" + encodedID},
		{"GET on instantiate, which answered 405", http.MethodGet, "/api/v1/templates/" + encodedID + "/instantiate"},
		{"GET on validate, which answered 405", http.MethodGet, "/api/v1/templates/" + encodedID + "/validate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pattern := r.mux.Handler(httptest.NewRequest(tc.method, tc.target, nil))
			if pattern != "/api/v1/" {
				t.Fatalf("%s %s dispatches to %q, want the /api/v1/ fallback — "+
					"a template pattern is still claiming more than one endpoint's worth of paths",
					tc.method, tc.target, pattern)
			}

			rec := httptest.NewRecorder()
			r.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if strings.Contains(rec.Body.String(), "<html") || strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s answered HTML (%d, content-type %q) — a JSON client would break on it",
					tc.method, tc.target, rec.Code, rec.Header().Get("Content-Type"))
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s answered %d, want 401: the request carries no credential and the fallback is "+
					"AuthenticatedOnly, so the chain must refuse before the 404 body", tc.method, tc.target, rec.Code)
			}
		})
	}

	// ⚠️ HEAD on the collection is the one answer that got *more* permissive, and
	// it is pinned here rather than left to be discovered: Go's mux matches HEAD
	// against a GET pattern, so it reaches the route instead of the fallback.
	if _, got := r.mux.Handler(httptest.NewRequest(http.MethodHead, "/api/v1/templates", nil)); got != "GET /api/v1/templates" {
		t.Errorf("HEAD /api/v1/templates dispatches to %q, want the GET route — the HEAD widening "+
			"recorded in module_templates.go's table no longer holds", got)
	}
}

// TestAPIFallback_RequestStrandedPaths is where the behaviour-change table on
// requestsModule.Routes is *measured* rather than reasoned about.
//
// ⛔ The first four rows are the point of the whole step, and they are the only
// rows in any of these five fallback tests where the *before* answer was a
// successful mutation on the wrong row: "/api/v1/evm/requests/" matched every verb
// at every depth, the closure picked the approval handler by
// strings.HasSuffix(path, "/approve"), and the handler read the id as the segment
// before the action — so POST /api/v1/evm/requests/a/b/approve answered 200 and
// approved request "b". Measured on the real registrations with a spy on
// ProcessApproval, not read off the source.
//
// ⚠️ The wrong-verb rows are *not* holes being closed. All four closure branches
// checked their method before doing anything, so each of those answered 405 and
// called nothing; they are status changes. Unlike presets, signers and hd-wallets,
// there was no verb that reached a write here.
//
// ⚠️ The handler-package tests for this module run against a bare mux with no
// fallback, so they see the mux's own 404 and 405. Here the real
// registerAPIFallback stands next to the real module, which is the only place the
// daemon's answer is visible: "/api/v1/" matches every path and every method, so
// ⛔ the daemon never answers 405 for these — every stranded shape, wrong-verb ones
// included, lands on the JSON 404 fallback. What must never happen is that it lands
// on the SPA and comes back text/html to a JSON client.
func TestAPIFallback_RequestStrandedPaths(t *testing.T) {
	requestsMod, err := NewRequestsModule(maximalRequestHandlers(t))
	if err != nil {
		t.Fatalf("building the requests module: %v", err)
	}

	var patterns []string
	requestsMod.Routes(patternCollector(func(pattern string, _ RouteAuth) {
		patterns = append(patterns, pattern)
	}))
	if len(patterns) != 6 {
		t.Fatalf("requestsModule registered %d patterns, want 6 — the rows below would pass for the wrong reason",
			len(patterns))
	}

	r := newChainedTestRouter()
	r.mountModules(requestsMod)
	r.handle("/", PublicUnwrapped("test fixture"), okHandler("<!doctype html><html>spa</html>"))
	r.registerAPIFallback()

	// ⭐ A request id as the daemon mints them: internal/core/service/sign.go uses
	// uuid.New().String(), so it is one slash-free segment and needs no encoding.
	const id = "3fa85f64-5717-4562-b3fc-2c963f66afa6"

	// Each real endpoint still resolves to its own pattern: the fallback shadows
	// none of them, and the decomposition left none of them behind.
	for _, pattern := range patterns {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Fatalf("request pattern %q has no method — the rows below assume method+path patterns", pattern)
		}
		target := strings.ReplaceAll(path, "{id}", id)
		if strings.Contains(target, "{") {
			t.Fatalf("request pattern %q has a wildcard this test does not know how to fill: %q", pattern, target)
		}
		if _, got := r.mux.Handler(httptest.NewRequest(method, target, nil)); got != pattern {
			t.Errorf("%s %s dispatches to %q, want its own route %q", method, target, got, pattern)
		}
	}

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		// ⛔ The four rows this step exists for: the depth swallow. The first three
		// reached a *mutation* with an id taken from the wrong segment.
		{"two segments, which approved \"b\"", http.MethodPost, "/api/v1/evm/requests/a/b/approve"},
		{"four segments, which approved \"d\"", http.MethodPost, "/api/v1/evm/requests/a/b/c/d/approve"},
		{"no id at all, which approved \"requests\"", http.MethodPost, "/api/v1/evm/requests/approve"},
		{"preview-rule two segments deep, which previewed for \"b\"", http.MethodPost, "/api/v1/evm/requests/a/b/preview-rule"},
		// ---- the same swallow on the reads: the last segment won ----
		{"a deep path, which answered with request \"c\"", http.MethodGet, "/api/v1/evm/requests/a/b/c"},
		{"an unknown sub-action, which answered with request \"unknown\"", http.MethodGet, "/api/v1/evm/requests/" + id + "/unknown"},
		{"simulation two segments deep", http.MethodGet, "/api/v1/evm/requests/a/b/simulation"},
		// ---- trailing slash, which the prefix forgave into an empty id ----
		{"the collection with a trailing slash, which read request \"\"", http.MethodGet, "/api/v1/evm/requests/"},
		{"an item with a trailing slash, which read request \"\"", http.MethodGet, "/api/v1/evm/requests/" + id + "/"},
		{"approve with a trailing slash, which answered 405", http.MethodPost, "/api/v1/evm/requests/" + id + "/approve/"},
		{"preview-rule with a trailing slash, which answered 405", http.MethodPost, "/api/v1/evm/requests/" + id + "/preview-rule/"},
		{"simulation with a trailing slash, which answered 404", http.MethodGet, "/api/v1/evm/requests/" + id + "/simulation/"},
		{"batch-approve with a trailing slash", http.MethodPost, "/api/v1/evm/requests/batch-approve/"},
		// ---- verbs no route declares; every one was the handler's own 405 ----
		{"PUT on the collection, which answered 405", http.MethodPut, "/api/v1/evm/requests"},
		{"POST on the collection, which answered 405", http.MethodPost, "/api/v1/evm/requests"},
		{"POST on an item, which answered 405", http.MethodPost, "/api/v1/evm/requests/" + id},
		{"GET on approve, which answered 405", http.MethodGet, "/api/v1/evm/requests/" + id + "/approve"},
		{"DELETE on approve, which answered 405", http.MethodDelete, "/api/v1/evm/requests/" + id + "/approve"},
		{"GET on preview-rule, which answered 405", http.MethodGet, "/api/v1/evm/requests/" + id + "/preview-rule"},
		{"POST on simulation, which answered 405", http.MethodPost, "/api/v1/evm/requests/" + id + "/simulation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pattern := r.mux.Handler(httptest.NewRequest(tc.method, tc.target, nil))
			if pattern != "/api/v1/" {
				t.Fatalf("%s %s dispatches to %q, want the /api/v1/ fallback — "+
					"a request pattern is still claiming more than one endpoint's worth of paths",
					tc.method, tc.target, pattern)
			}

			rec := httptest.NewRecorder()
			r.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if strings.Contains(rec.Body.String(), "<html") || strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s answered HTML (%d, content-type %q) — a JSON client would break on it",
					tc.method, tc.target, rec.Code, rec.Header().Get("Content-Type"))
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s answered %d, want 401: the request carries no credential and the fallback is "+
					"AuthenticatedOnly, so the chain must refuse before the 404 body", tc.method, tc.target, rec.Code)
			}
		})
	}

	// ⚠️ GET on the batch-approve path is *not* in the table above, and measuring it
	// is why: "batch-approve" is a legal single segment, so it dispatches to the item
	// route with that id — which is what the closure's default branch made of it too.
	// ⭐ It is also the one pattern overlap in this set, and the mux resolving it by
	// specificity is a property worth pinning rather than a reading of the rules.
	if _, got := r.mux.Handler(httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/batch-approve", nil)); got != "GET /api/v1/evm/requests/{id}" {
		t.Errorf("GET /api/v1/evm/requests/batch-approve dispatches to %q, want the item route", got)
	}
	if _, got := r.mux.Handler(httptest.NewRequest(http.MethodPost, "/api/v1/evm/requests/batch-approve", nil)); got != "POST /api/v1/evm/requests/batch-approve" {
		t.Errorf("POST /api/v1/evm/requests/batch-approve dispatches to %q, want the literal batch route", got)
	}

	// ⚠️ The two HEAD rows are the answers that got *more* permissive, pinned here
	// rather than left to be discovered: Go's mux matches HEAD against a GET
	// pattern, so both reads reach their route instead of the fallback.
	for _, tc := range []struct{ target, want string }{
		{"/api/v1/evm/requests", "GET /api/v1/evm/requests"},
		{"/api/v1/evm/requests/" + id, "GET /api/v1/evm/requests/{id}"},
	} {
		if _, got := r.mux.Handler(httptest.NewRequest(http.MethodHead, tc.target, nil)); got != tc.want {
			t.Errorf("HEAD %s dispatches to %q, want the GET route %q — the HEAD widening recorded in "+
				"module_requests.go's table no longer holds", tc.target, got, tc.want)
		}
	}
}

// TestAPIFallback_HDWalletAndAPIKeyStrandedPaths is the S4 twin of
// TestAPIFallback_WalletDeepPathAndWrongMethod, and it is where the
// behaviour-change tables on hdWalletsModule.Routes and apiKeysModule.Routes are
// *measured* rather than reasoned about.
//
// ⚠️ The handler-package tests for these two modules run against a bare mux with
// no fallback, so they see the mux's own 404 and 405. This one runs the real
// registerAPIFallback next to the real modules, which is the only place the
// daemon's answer is visible: "/api/v1/" matches every method and every depth,
// so a stranded path lands there — 401 without a credential, and a JSON 404 with
// one. ⛔ What must never happen is that it lands on the SPA and comes back
// text/html to a client parsing JSON.
func TestAPIFallback_HDWalletAndAPIKeyStrandedPaths(t *testing.T) {
	hdMod, err := NewHDWalletsModule(maximalHDWalletHandler(t))
	if err != nil {
		t.Fatalf("building the hd-wallets module: %v", err)
	}
	apiKeysMod, err := NewAPIKeysModule(maximalAPIKeyHandler(t))
	if err != nil {
		t.Fatalf("building the api-keys module: %v", err)
	}

	// Collect the real patterns so the "still reaches its own route" rows are
	// generated rather than restated.
	var patterns []string
	collect := patternCollector(func(pattern string, _ RouteAuth) { patterns = append(patterns, pattern) })
	hdMod.Routes(collect)
	apiKeysMod.Routes(collect)
	if len(patterns) != 10 {
		t.Fatalf("the two modules registered %d patterns, want 10 — the rows below would pass for the wrong reason", len(patterns))
	}

	r := newChainedTestRouter()
	r.mountModules(hdMod, apiKeysMod)
	r.handle("/", PublicUnwrapped("test fixture"), okHandler("<!doctype html><html>spa</html>"))
	r.registerAPIFallback()

	const addr = "0x1111111111111111111111111111111111111111"

	for _, pattern := range patterns {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Fatalf("pattern %q has no method — the rows below assume method+path patterns", pattern)
		}
		target := strings.NewReplacer("{address}", addr, "{id}", "k-1").Replace(path)
		if strings.Contains(target, "{") {
			t.Fatalf("pattern %q has a wildcard this test does not know how to fill: %q", pattern, target)
		}
		if _, got := r.mux.Handler(httptest.NewRequest(method, target, nil)); got != pattern {
			t.Errorf("%s %s dispatches to %q, want its own route %q", method, target, got, pattern)
		}
	}

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		// ---- hd-wallets: what the two wildcard prefixes used to swallow ----
		{"hd list with a trailing slash, which served the list before", http.MethodGet, "/api/v1/evm/hd-wallets/"},
		{"hd create with a trailing slash, which created before", http.MethodPost, "/api/v1/evm/hd-wallets/"},
		{"derive with a trailing slash, which derived before", http.MethodPost, "/api/v1/evm/hd-wallets/" + addr + "/derive/"},
		{"derived with a trailing slash, which listed before", http.MethodGet, "/api/v1/evm/hd-wallets/" + addr + "/derived/"},
		// ⛔ This row is the one worth reading twice: the prefix matched every
		// method, so a GET reached deriveAddresses — a write behind a read verb.
		{"GET on derive, which used to run a derivation", http.MethodGet, "/api/v1/evm/hd-wallets/" + addr + "/derive"},
		{"an hd wallet with no action, which answered 404 unknown action", http.MethodGet, "/api/v1/evm/hd-wallets/" + addr},
		{"an unknown hd action", http.MethodGet, "/api/v1/evm/hd-wallets/" + addr + "/unknown"},
		{"a non-address, which answered 400 invalid path or address", http.MethodGet, "/api/v1/evm/hd-wallets/not-an-address"},
		{"a method no hd-wallet route serves", http.MethodPut, "/api/v1/evm/hd-wallets"},
		// ---- api-keys: what the two method-less prefixes used to swallow ----
		{"the bare api-keys prefix, which answered 400 ID is required", http.MethodGet, "/api/v1/api-keys/"},
		{"an api key with a trailing slash", http.MethodGet, "/api/v1/api-keys/k-1/"},
		{"an api-key deep path", http.MethodGet, "/api/v1/api-keys/a/b"},
		{"a method no api-key item route serves", http.MethodPatch, "/api/v1/api-keys/k-1"},
		{"a method no api-key collection route serves", http.MethodPut, "/api/v1/api-keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pattern := r.mux.Handler(httptest.NewRequest(tc.method, tc.target, nil))
			if pattern != "/api/v1/" {
				t.Fatalf("%s %s dispatches to %q, want the /api/v1/ fallback — "+
					"a pattern is still claiming more than one endpoint's worth of paths",
					tc.method, tc.target, pattern)
			}

			rec := httptest.NewRecorder()
			r.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if strings.Contains(rec.Body.String(), "<html") || strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s answered HTML (%d, content-type %q) — a JSON client would break on it",
					tc.method, tc.target, rec.Code, rec.Header().Get("Content-Type"))
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s answered %d, want 401: the request carries no credential and the fallback is "+
					"AuthenticatedOnly, so the chain must refuse before the 404 body", tc.method, tc.target, rec.Code)
			}
		})
	}
}
