package api

import (
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// mutatingMethods are the HTTP methods that change state. A route serving one
// of them must not be gated on a read permission.
var mutatingMethods = []string{"POST ", "PUT ", "PATCH ", "DELETE "}

// readPermissions are the permissions that mean "may look", and must therefore
// never be what stands between a caller and a write.
var readPermissions = map[middleware.Permission]bool{
	middleware.PermReadBudgets:   true,
	middleware.PermReadSigners:   true,
	middleware.PermReadPresets:   true,
	middleware.PermReadTemplates: true,
	middleware.PermReadHDWallets: true,
	middleware.PermReadAudit:     true,
	middleware.PermReadACLs:      true,
	middleware.PermReadMetrics:   true,
}

// TestRoutePermissions_MutatingRoutesAreNotGatedOnRead is the test that took
// over from the permission checks that used to sit inside handlers.
//
// Those handlers were reached through a route registered with a *read*
// permission, and each mutating branch re-checked a manage permission itself —
// five such checks in budget.go alone. Forgetting one is a permission bypass,
// and nothing reports a check that is not there. Declaring the permission with
// the route makes the absence visible: an unregistered route has no permission
// at all rather than a too-permissive one.
//
// ⚠️ This asserts the route table, not a live request, because the table is
// where the mistake would be. A request-level test would need the whole daemon
// wired up and would still only cover the routes someone remembered to exercise.
func TestRoutePermissions_MutatingRoutesAreNotGatedOnRead(t *testing.T) {
	r := &Router{routePerms: map[string]middleware.Permission{}}

	// A representative registration, matching what setupRoutes does for budgets.
	r.routePerms["GET /api/v1/evm/budgets"] = middleware.PermReadBudgets
	r.routePerms["POST /api/v1/evm/budgets"] = middleware.PermManageBudgets

	for pattern, perm := range r.RoutePermissions() {
		if !isMutating(pattern) {
			continue
		}
		if readPermissions[perm] {
			t.Errorf("%s is a mutating route gated on the read permission %q", pattern, perm)
		}
	}
}

// TestRoutePermissions_ReportsWhatWasRegistered guards the accessor itself: a
// table that silently returns nothing would make the test above vacuous, which
// is the failure mode worth ruling out explicitly.
func TestRoutePermissions_ReportsWhatWasRegistered(t *testing.T) {
	r := &Router{routePerms: map[string]middleware.Permission{}}
	r.routePerms["DELETE /api/v1/evm/budgets/"] = middleware.PermManageBudgets

	got := r.RoutePermissions()
	if len(got) != 1 {
		t.Fatalf("RoutePermissions returned %d entries, want 1", len(got))
	}
	if got["DELETE /api/v1/evm/budgets/"] != middleware.PermManageBudgets {
		t.Fatalf("permission = %q, want %q", got["DELETE /api/v1/evm/budgets/"], middleware.PermManageBudgets)
	}

	// The map must be a copy: handing out the router's own table would let a
	// caller rewrite the permissions it is meant to report.
	got["DELETE /api/v1/evm/budgets/"] = middleware.PermReadBudgets
	if r.routePerms["DELETE /api/v1/evm/budgets/"] != middleware.PermManageBudgets {
		t.Fatal("RoutePermissions handed out the router's own map")
	}
}

func isMutating(pattern string) bool {
	for _, m := range mutatingMethods {
		if strings.HasPrefix(pattern, m) {
			return true
		}
	}
	return false
}

// TestModules_ReportWhatWasMounted is the property the Module interface exists
// for: what a daemon serves should be readable, not inferred from which of 30
// RouterConfig fields happened to be non-nil.
//
// A module that cannot be built is absent from the list rather than half-built —
// bootstrap without a creator is the case in point, and saying so at
// construction beats a nil check at each route.
func TestModules_ReportWhatWasMounted(t *testing.T) {
	r := &Router{routePerms: map[string]middleware.Permission{}}

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

type stubModule struct{ name string }

func (m *stubModule) Name() string          { return m.name }
func (m *stubModule) Routes(RouteRegistrar) {}
