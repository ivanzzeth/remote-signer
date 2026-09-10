package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// ⚠️ What this file replaced, and why the replacement is not the same test.
//
// It used to be route_permissions_test.go, and its headline test built
// `&Router{routePerms: map[string]middleware.Permission{}}`, wrote two rows into
// it by hand, and asserted over those two rows. setupRoutes was never called.
// The property it claimed — "no mutating route is gated on a read permission" —
// was therefore checked against a fixture the test itself had just written, and
// it would have stayed green with every one of the 55 real routes gated wrong.
// A test whose name promises route-permission coverage while covering two
// synthetic rows is worse than no test: it answers the question "is anyone
// watching this?" with yes.
//
// ⭐ That property now lives where it can see every registration, including the
// ones inside `if r.config.X != nil` that no live-router fixture would build:
// the `route-mutating-perm` check in cmd/archcheck/routeauth.go reads the
// registration call sites out of the source. What is left here is what a Go
// test can actually prove — that the mechanism itself behaves — and it is all
// exercised against a real *Router and a real *http.ServeMux.

// newTestRouter builds the smallest Router that can register and dispatch. It
// takes no dependencies on purpose: everything below tests the registration
// mechanism, and a fixture needing a database would push these tests into a
// slower layer for no gain.
func newTestRouter() *Router {
	return &Router{mux: http.NewServeMux(), routeAuth: map[string]RouteAuth{}}
}

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
}

// TestRouteAuth_UndeclaredPatternIsDenied is Layer 3.
//
// ⚠️ Before this change the answer to "what happens when a request hits a route
// with no entry in the permission table?" was: nothing happens. The table was
// written by handlePerm and read only by RoutePermissions(); no middleware
// consulted it, so a pattern registered without RequirePermission simply had no
// permission check in its chain. "Absent from the table" and "allowed for every
// role" were indistinguishable.
//
// The bypass is simulated the only way it can occur now — a direct mux.Handle,
// which is what the archcheck gate forbids and what a _test.go or build-tagged
// file could still do, since cmd/archcheck/repo.go does not parse those.
func TestRouteAuth_UndeclaredPatternIsDenied(t *testing.T) {
	r := newTestRouter()
	r.handle("GET /declared", Public("test fixture"), okHandler("declared"))
	// ⛔ Exactly the shape the gate bans, on purpose: this is the thing Layer 3
	// exists to catch when Layers 1 and 2 cannot see the file.
	r.mux.Handle("GET /smuggled", okHandler("smuggled"))

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/smuggled", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("undeclared route answered %d, want %d — the handler ran with no authorization decision behind it",
			rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), "smuggled") {
		t.Fatalf("undeclared handler produced output: %q", rec.Body.String())
	}
}

func TestRouteAuth_DeclaredPatternIsServed(t *testing.T) {
	r := newTestRouter()
	r.handle("GET /declared", Public("test fixture"), okHandler("declared"))

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/declared", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "declared" {
		t.Fatalf("declared route answered %d %q, want 200 \"declared\"", rec.Code, rec.Body.String())
	}
}

// TestRouteAuth_UnmatchedRequestKeepsItsOwnAnswer pins the deliberate hole in
// the guard: it denies patterns, not requests. A 404 must stay a 404 — turning
// it into a 403 would tell a prober which paths exist.
func TestRouteAuth_UnmatchedRequestKeepsItsOwnAnswer(t *testing.T) {
	r := newTestRouter()
	r.handle("POST /declared", Public("test fixture"), okHandler("declared"))

	for _, tc := range []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"no such path", http.MethodGet, "/nothing-here", http.StatusNotFound},
		{"wrong method", http.MethodGet, "/declared", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if rec.Code != tc.want {
				t.Fatalf("answered %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// TestRouteAuth_UndecidedRegistrationPanics covers the one hole Layer 1 cannot
// close at compile time: inside package api the zero value of RouteAuth is
// writable. It must not be servable.
func TestRouteAuth_UndecidedRegistrationPanics(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth RouteAuth
		want string
	}{
		{"zero value", RouteAuth{}, "no authorization decision"},
		{"exemption with no reason", Public(""), "no reason"},
		{"authenticated-only with no reason", AuthenticatedOnly(""), "no reason"},
		{"unwrapped with no reason", PublicUnwrapped(""), "no reason"},
		{"permitted with no permission", Permitted(""), "empty permission"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				got, ok := recover().(string)
				if !ok {
					t.Fatalf("registration did not panic — a route with %v would have been served", tc.auth)
				}
				if !strings.Contains(got, tc.want) {
					t.Fatalf("panic = %q, want it to mention %q", got, tc.want)
				}
			}()
			newTestRouter().handle("GET /x", tc.auth, okHandler("x"))
		})
	}
}

// TestRouteAuth_DuplicatePatternPanics: http.ServeMux panics on a duplicate
// pattern anyway, but it does so after the second registration has already
// overwritten nothing — and its message says nothing about which decision won.
// Failing first, with both decisions in the message, is the difference between
// a five-minute fix and a long one.
func TestRouteAuth_DuplicatePatternPanics(t *testing.T) {
	defer func() {
		got, ok := recover().(string)
		if !ok {
			t.Fatal("registering the same pattern twice did not panic")
		}
		if !strings.Contains(got, "registered twice") {
			t.Fatalf("panic = %q, want it to mention the duplicate", got)
		}
	}()
	r := newTestRouter()
	r.handle("GET /x", Public("first"), okHandler("x"))
	r.handle("GET /x", Permitted(middleware.PermReadAudit), okHandler("x"))
}

// TestRouteAuthorizations_ReportsEveryShape guards the accessors: a table that
// silently dropped the exempt routes would make the exemption list look empty,
// which is the failure mode worth ruling out explicitly.
func TestRouteAuthorizations_ReportsEveryShape(t *testing.T) {
	r := newTestRouter()
	r.handle("GET /a", Permitted(middleware.PermReadAudit), okHandler("a"))
	r.handle("GET /b", Public("public fixture"), okHandler("b"))

	all := r.RouteAuthorizations()
	if len(all) != 2 {
		t.Fatalf("RouteAuthorizations returned %d entries, want 2", len(all))
	}
	if !all["GET /b"].Exempt() || all["GET /b"].Reason() != "public fixture" {
		t.Fatalf("exempt route came back as %v", all["GET /b"])
	}
	if perm, ok := all["GET /a"].Permission(); !ok || perm != middleware.PermReadAudit {
		t.Fatalf("permitted route came back as %v", all["GET /a"])
	}

	// RoutePermissions is the narrower view: permitted routes only. ⚠️ Absent
	// means "declared no permission", not "unknown" — that distinction is the
	// whole point of the wider table existing.
	perms := r.RoutePermissions()
	if len(perms) != 1 || perms["GET /a"] != middleware.PermReadAudit {
		t.Fatalf("RoutePermissions() = %v, want just the permitted route", perms)
	}

	// Both maps must be copies; handing out the router's own would let a caller
	// rewrite the record of what it is enforcing.
	all["GET /a"] = Public("tampered")
	perms["GET /a"] = middleware.PermReadBudgets
	if got, _ := r.RouteAuthorizations()["GET /a"].Permission(); got != middleware.PermReadAudit {
		t.Fatal("RouteAuthorizations handed out the router's own map")
	}
}

// TestModules_ReportWhatWasMounted is the property the Module interface exists
// for: what a daemon serves should be readable, not inferred from which of 30
// RouterConfig fields happened to be non-nil.
//
// A module that cannot be built is absent from the list rather than half-built —
// bootstrap without a creator is the case in point, and saying so at
// construction beats a nil check at each route.
func TestModules_ReportWhatWasMounted(t *testing.T) {
	r := newTestRouter()

	// A module whose precondition is unmet returns nil and must not appear.
	r.mountModules(NewBootstrapModule(nil, nil, nil))
	if got := r.Modules(); len(got) != 0 {
		t.Fatalf("mounted %v, want nothing — bootstrap has no creator", got)
	}

	r.mountModules(&stubModule{name: "stub"})
	got := r.Modules()
	if len(got) != 1 || got[0] != "stub" {
		t.Fatalf("Modules() = %v, want [stub]", got)
	}

	// The slice must be a copy; handing out the router's own would let a caller
	// rewrite the record of what is served.
	got[0] = "tampered"
	if r.Modules()[0] != "stub" {
		t.Fatal("Modules() handed out the router's own slice")
	}
}

// TestModules_RegisterThroughTheSameEntryPoint: a module's routes have to land
// in the same table as the router's own, or the exemption list is blind to half
// the surface — which is exactly what reg.Public/reg.Authenticated used to do.
func TestModules_RegisterThroughTheSameEntryPoint(t *testing.T) {
	r := newTestRouter()
	r.mountModules(&stubModule{name: "stub", routes: func(reg RouteRegistrar) {
		reg.Handle("GET /stub", Public("stub fixture"), okHandler("stub"))
	}})

	auth, ok := r.RouteAuthorizations()["GET /stub"]
	if !ok {
		t.Fatal("a module route is missing from the authorization table")
	}
	if !auth.Exempt() || auth.Reason() != "stub fixture" {
		t.Fatalf("module route recorded as %v", auth)
	}
}

type stubModule struct {
	name   string
	routes func(RouteRegistrar)
}

func (m *stubModule) Name() string { return m.name }
func (m *stubModule) Routes(reg RouteRegistrar) {
	if m.routes != nil {
		m.routes(reg)
	}
}
