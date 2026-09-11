package api

import (
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// ---------- Layer 1: saying nothing about authorization is not representable ----------
//
// # The failure this exists to remove
//
// Routes used to be registered in five different shapes. Only one of them —
// handlePerm — recorded what it had decided, so RoutePermissions() described
// fewer than half the mux patterns and the route table could not answer the one
// question worth asking: *is there a route here that nobody made a decision
// about?* A pattern registered as `r.mux.Handle(p, r.withAuth(h))` looked
// exactly like a deliberate "authenticated, no permission needed" and exactly
// like "somebody forgot", and nothing could tell them apart — least of all a
// reviewer reading a 490-line setupRoutes with 13 conditional branches.
//
// # The shape now
//
// There is one registration entry point, (*Router).handle, and RouteAuth is a
// required positional argument to it. RouteAuth has no useful zero value: every
// way of building one either names a permission or states, in a string that has
// to be written by hand, why the route does not have one.
//
// ⚠️ How far this reaches, precisely — the guarantee is *not* "the compiler
// rejects a route with no authorization decision":
//
//   - ✅ Omitting the argument does not compile. That is the common mistake and
//     it is gone.
//   - ✅ Reaching the mux without going through handle is impossible outside
//     package api: the field is unexported.
//   - ⚠️ Inside package api the composite literal `RouteAuth{}` is still
//     writable, and Go has no way to forbid it. It is rejected at startup by
//     handle (the daemon panics rather than serving an undecided route) and
//     statically by the archcheck `route-auth` gate, which bans the literal
//     outside this file. Compile-time it is not.
//   - ⚠️ A file that archcheck cannot see — a _test.go file or one behind a
//     build tag; see cmd/archcheck/repo.go:39-88 — is covered only by the
//     startup panic and by the runtime guard in Handler().
//
// That is why there are three layers and not one. Layer 2 is the archcheck gate
// (cmd/archcheck/routeauth.go), Layer 3 is Handler()'s deny-by-default lookup.
//
// # ⛔ Known limit, and it is not small
//
// A prefix pattern serving many endpoints can only declare ONE permission.
//
// ⚠️ The example this paragraph used to give — `/api/v1/evm/rules/` declaring
// PermListRules for all twelve endpoints behind it — is gone: proposal S8 named
// those twelve, and the eight mutating ones are now eight lines of
// route-mutating-perm.txt rather than one invisible fact. ⛔ That is the shape of
// the fix, not the end of it: the permissions did not change, they became
// *visible*, and handler/evm/rule.go still checks admin inside the handler for
// both validate endpoints. So "every route declares a permission" remains
// satisfiable while the per-endpoint permissions are still wrong, and this
// mechanism still cannot see that: it counts patterns and reads the permission
// each one declares, and neither tells it whether that permission is the right
// one.
//
// ⚠️ Method-less prefixes that still serve more than one endpoint:
// `/api/v1/evm/simulations` and `/api/v1/evm/guard/resume`. The remaining
// wildcards (`GET /api/v1/evm/budgets/` and friends) at least carry a method.
//
// ⭐ Its value before the handler decomposition (proposal S3–S8) is therefore
// narrower than it sounds, and worth stating plainly: it does not make today's
// permissions right — it makes every route the decomposition creates declare a
// permission *at birth*, and it makes the routes that declare none a finite,
// reasoned, self-expiring list instead of a thing you would have to re-derive
// by reading setupRoutes.

// routeAuthMode is what kind of decision a registration made. The zero value is
// deliberately "none was made", so a RouteAuth that nobody built through a
// constructor fails loudly instead of defaulting to something permissive.
type routeAuthMode int

const (
	authUndeclared routeAuthMode = iota
	authPermitted
	authAuthenticatedOnly
	authPublic
	authPublicUnwrapped
)

func (m routeAuthMode) String() string {
	switch m {
	case authPermitted:
		return "permitted"
	case authAuthenticatedOnly:
		return "authenticated-only"
	case authPublic:
		return "public"
	case authPublicUnwrapped:
		return "public-unwrapped"
	default:
		return "undeclared"
	}
}

// RouteAuth is what a registration says about authorization. Build it with
// Permitted, AuthenticatedOnly, Public or PublicUnwrapped — the fields are
// unexported so that a value from outside package api cannot be undecided.
type RouteAuth struct {
	mode   routeAuthMode
	perm   middleware.Permission
	reason string
}

// Permitted gates the route on perm, checked by middleware.RequirePermission
// after authentication. This is the default and the only shape that needs no
// justification: the permission is the justification.
func Permitted(perm middleware.Permission) RouteAuth {
	return RouteAuth{mode: authPermitted, perm: perm}
}

// AuthenticatedOnly registers a route that requires a valid API key but no
// particular permission.
//
// ⛔ reason is not documentation, it is the exemption itself. It must say why
// no permission applies — normally because the decision is per-row or
// per-resource and a route cannot make it — or, when the honest answer is that
// this is a gap nobody has closed yet, say *that*. A reason nobody can disagree
// with ("internal endpoint") is the same as no reason: 没有理由的豁免等于关掉检查.
func AuthenticatedOnly(reason string) RouteAuth {
	return RouteAuth{mode: authAuthenticatedOnly, reason: reason}
}

// Public registers a route reachable with no credentials, wrapped in the
// standard security headers and nothing else.
func Public(reason string) RouteAuth {
	return RouteAuth{mode: authPublic, reason: reason}
}

// PublicUnwrapped is Public without even middleware.SecurityHeadersMiddleware.
//
// ⚠️ It exists for exactly one route and should stay that way: the SPA
// catch-all. SecurityHeadersMiddleware sets `Content-Security-Policy:
// default-src 'none'`, which is right for an API and fatal for the HTML+JS
// bundle the web handler serves.
func PublicUnwrapped(reason string) RouteAuth {
	return RouteAuth{mode: authPublicUnwrapped, reason: reason}
}

// Permission reports the permission this route is gated on, and whether it has
// one at all.
func (a RouteAuth) Permission() (middleware.Permission, bool) {
	return a.perm, a.mode == authPermitted
}

// Reason is the written justification for a route that carries no permission.
// Empty for a permitted route.
func (a RouteAuth) Reason() string { return a.reason }

// Exempt reports whether this route carries no permission — i.e. whether it is
// one of the entries the exemption list has to account for.
func (a RouteAuth) Exempt() bool {
	return a.mode == authAuthenticatedOnly || a.mode == authPublic || a.mode == authPublicUnwrapped
}

// Mode is the registration shape, as the archcheck baseline spells it
// ("permitted", "authenticated-only", "public", "public-unwrapped"). The
// baseline keys on it so that a route moving between shapes — an exemption
// becoming public, say — has to be re-reviewed rather than silently kept.
func (a RouteAuth) Mode() string { return a.mode.String() }

func (a RouteAuth) String() string {
	if a.mode == authPermitted {
		return fmt.Sprintf("permitted(%s)", a.perm)
	}
	return fmt.Sprintf("%s(%q)", a.mode, a.reason)
}

// validate rejects the two values a constructor cannot produce but a composite
// literal can: no decision at all, and an exemption with nothing written in it.
func (a RouteAuth) validate() error {
	switch a.mode {
	case authUndeclared:
		return fmt.Errorf("no authorization decision: use Permitted(perm), or AuthenticatedOnly/Public/PublicUnwrapped with a reason")
	case authPermitted:
		if a.perm == "" {
			return fmt.Errorf("permitted route with an empty permission")
		}
	default:
		if a.reason == "" {
			return fmt.Errorf("%s route with no reason — 没有理由的豁免等于关掉检查", a.mode)
		}
	}
	return nil
}

// handle is the one place a pattern reaches the mux.
//
// ⛔ Nothing else may call r.mux.Handle. That is enforced by the archcheck
// `route-auth` gate rather than by the compiler, because the mux field is
// reachable from anywhere inside package api.
//
// It panics on an undecided or unreasoned RouteAuth. A panic here happens at
// NewRouter, i.e. at daemon start, deterministically and before the listener
// exists — it cannot be triggered by a request. The alternative, returning an
// error, would have to be checked at 55 call sites, and the one place someone
// forgets to check it is the place the route ships undecided.
func (r *Router) handle(pattern string, auth RouteAuth, h http.Handler) {
	if err := auth.validate(); err != nil {
		panic(fmt.Sprintf("route %q: %v", pattern, err))
	}
	if prev, dup := r.routeAuth[pattern]; dup {
		panic(fmt.Sprintf("route %q registered twice: %s then %s", pattern, prev, auth))
	}
	r.routeAuth[pattern] = auth
	r.mux.Handle(pattern, r.wrapForAuth(auth, h))
}

// wrapForAuth builds the middleware chain a decision implies. ⚠️ Each arm is
// byte-for-byte the chain the corresponding registration shape used before this
// converged; changing one changes who can reach a route.
func (r *Router) wrapForAuth(auth RouteAuth, h http.Handler) http.Handler {
	switch auth.mode {
	case authPermitted:
		return r.withAuthAndPerm(auth.perm, h)
	case authAuthenticatedOnly:
		return r.withAuth(h)
	case authPublic:
		return middleware.SecurityHeadersMiddleware()(h)
	case authPublicUnwrapped:
		return h
	default:
		panic("unreachable: validate() rejects every other mode")
	}
}

// RouteAuthorizations returns what every registered pattern declared. The map
// is a copy: handing out the router's own would let a caller rewrite the record
// of what it is enforcing.
func (r *Router) RouteAuthorizations() map[string]RouteAuth {
	out := make(map[string]RouteAuth, len(r.routeAuth))
	for k, v := range r.routeAuth {
		out[k] = v
	}
	return out
}

// RoutePermissions returns the permission each permitted pattern requires.
// Exempt routes are absent — ⚠️ absent because they declared no permission, not
// because nothing is known about them; RouteAuthorizations is the whole table.
func (r *Router) RoutePermissions() map[string]middleware.Permission {
	out := make(map[string]middleware.Permission, len(r.routeAuth))
	for k, v := range r.routeAuth {
		if perm, ok := v.Permission(); ok {
			out[k] = perm
		}
	}
	return out
}

// ---------- Layer 3: deny by default at dispatch ----------
//
// # What was actually there before (verified, not assumed)
//
// Nothing. routePerms was a *recording* map: handlePerm wrote to it and only
// RoutePermissions() ever read it. No middleware consulted it, and
// middleware.RequirePermission is only ever installed by withAuthAndPerm — so a
// pattern registered without it simply had no permission check in its chain and
// the request proceeded. "Not in the table" and "allowed for every role" were
// the same state, and the table was not consulted at request time at all.
//
// # What it is now
//
// Handler() resolves the pattern the mux would match *before* dispatching, and
// a pattern the router did not register through handle is refused. Today that
// set is empty by construction, so this changes no behaviour; it is here for
// the case Layers 1 and 2 cannot see — a registration added from a _test.go or
// build-tagged file, which archcheck does not parse, or a future edit to this
// package that gets at the mux some way the gate does not recognise.
//
// ⚠️ An empty pattern means the mux matched no route of ours (404, 405, or a
// redirect it will issue itself). Those are left alone deliberately: denying
// them would turn a 404 into a 403 and leak which paths exist.
//
// ⚠️ Cost: one extra trie lookup per request, since ServeMux.Handler does not
// populate PathValue and dispatching its result would silently break every
// wildcard route the decomposition is about to add. Correctness over the
// microsecond.
func (r *Router) denyUndeclared(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, pattern := r.mux.Handler(req); pattern != "" {
			if _, ok := r.routeAuth[pattern]; !ok {
				if r.logger != nil {
					r.logger.Error("route reached the mux without an authorization declaration; denying",
						"pattern", pattern,
						"method", req.Method,
						"path", req.URL.Path,
					)
				}
				http.Error(w, "forbidden: route has no authorization declaration", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}
