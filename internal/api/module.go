package api

import "net/http"

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
//
// ⚠️ It used to have three methods — Public / Authenticated / Permitted — and
// two of them recorded nothing, so a module's routes were absent from the
// authorization table and `Public` cost the same keystrokes as the two shapes
// that do enforce something. One method taking a required RouteAuth removes
// that: whatever a module says, it has to say it, and the table sees it.
type RouteRegistrar interface {
	// Handle registers pattern behind auth. Build auth with Permitted,
	// AuthenticatedOnly, Public or PublicUnwrapped — the exemption
	// constructors take the reason as an argument, so registering a route
	// without an authorization decision does not compile.
	Handle(pattern string, auth RouteAuth, h http.Handler)
}

// routerRegistrar adapts *Router to RouteRegistrar. It delegates to the single
// registration entry point rather than reaching for the mux, so a module route
// is recorded exactly like a router route.
type routerRegistrar struct{ r *Router }

func (rr routerRegistrar) Handle(pattern string, auth RouteAuth, h http.Handler) {
	rr.r.handle(pattern, auth, h)
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
