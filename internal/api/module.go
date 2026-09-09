package api

import (
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// Module is one feature's slice of the HTTP surface: it holds its own
// dependencies and registers its own routes.
//
// # Why
//
// RouterConfig grew to 40 fields, most of them carrying a comment along the
// lines of "optional: nil → this route is not registered". That makes the API
// surface a function of which fields happened to be non-nil at wiring time, and
// there is no way to read setupRoutes — 466 lines of nested `if` — and say what
// a running daemon actually serves. Adding a feature meant adding a field, and
// the field's absence silently removed endpoints.
//
// A module states its own precondition instead. It is constructed with what it
// needs or it is not constructed at all, and Routes() enumerates exactly what
// it serves.
//
// ⚠️ This is being adopted incrementally: the modules below have moved, the
// rest of setupRoutes has not. The router_config_fields ratchet tracks the
// remainder. ⛔ Adding a new feature by putting another field on RouterConfig
// takes that number the wrong way — write a Module.
type Module interface {
	// Name identifies the module in errors and in the route listing.
	Name() string
	// Routes registers the module's patterns. It is called once, at setup.
	Routes(reg RouteRegistrar)
}

// RouteRegistrar is the subset of Router a module may use. Narrow on purpose:
// a module registers routes and nothing else — it cannot reach back into the
// router's other state, which is what kept setupRoutes able to grow.
type RouteRegistrar interface {
	// Public registers a pattern reachable without authentication.
	Public(pattern string, h http.Handler)
	// Authenticated registers a pattern requiring a valid API key.
	Authenticated(pattern string, h http.Handler)
	// Permitted registers a pattern requiring a valid API key with perm.
	Permitted(pattern string, perm middleware.Permission, h http.Handler)
}

// routerRegistrar adapts *Router to RouteRegistrar.
type routerRegistrar struct{ r *Router }

func (rr routerRegistrar) Public(pattern string, h http.Handler) {
	rr.r.mux.Handle(pattern, middleware.SecurityHeadersMiddleware()(h))
}

func (rr routerRegistrar) Authenticated(pattern string, h http.Handler) {
	rr.r.mux.Handle(pattern, rr.r.withAuth(h))
}

func (rr routerRegistrar) Permitted(pattern string, perm middleware.Permission, h http.Handler) {
	rr.r.handlePerm(pattern, perm, h)
}

// mountModules registers every module that was constructed. A module that could
// not be built is simply absent from the slice — its precondition is checked
// where it is constructed, not by a nil check at each use.
func (r *Router) mountModules(mods ...Module) {
	reg := routerRegistrar{r: r}
	for _, m := range mods {
		if m == nil {
			continue
		}
		r.modules = append(r.modules, m.Name())
		m.Routes(reg)
	}
}

// Modules lists the modules this router mounted, so a caller — or a test — can
// see what the daemon serves without inferring it from nil checks.
func (r *Router) Modules() []string {
	out := make([]string, len(r.modules))
	copy(out, r.modules)
	return out
}
