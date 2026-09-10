package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// ---------- route-auth: nobody gets to the mux without saying something ----------
//
// # The failure
//
// 55 mux patterns were registered in five shapes and only one of them recorded
// what it had decided, so the router's permission table covered fewer than half
// the surface. `r.mux.Handle(p, r.withAuth(h))` was indistinguishable from a
// deliberate "authenticated, no permission needed" and from "somebody forgot",
// and neither the table nor any test could tell them apart.
//
// Layer 1 (internal/api/route_auth.go) makes the decision a required argument
// to one entry point, (*Router).handle. This is Layer 2: it asserts that the
// entry point is the *only* way to the mux, and that every route which declines
// to name a permission says in writing why.
//
// ⚠️ Layer 2 cannot see everything, and it is important to know which part:
// cmd/archcheck/repo.go:39-88 parses only files that ship in the binary — no
// _test.go, no build-tagged file. A registration smuggled in from an e2e helper
// is invisible here. That is what Layer 3 (the deny-by-default lookup in
// Router.Handler) is for.
//
// # ⛔ The limit this gate does not remove
//
// A prefix pattern serving many endpoints declares one permission for all of
// them. `/api/v1/evm/rules/` declares PermListRules while handler/evm/rule.go
// separately checks admin inside the handler for `validate`. "Every route
// declares a permission" is therefore satisfiable today while the per-endpoint
// permissions are still wrong, and nothing in this file can see that — it reads
// patterns, and a pattern is not an endpoint. The gate reaches full strength
// only after the handler decomposition (proposal S3–S8). ⭐ What it is worth
// before then: every route that decomposition creates has to declare a
// permission at birth, and the routes that declare none are a finite list with
// reasons attached that expires by itself.

// the four ways a RouteAuth can be built, and whether it is an exemption.
var routeAuthCtors = map[string]bool{
	"Permitted":         false,
	"AuthenticatedOnly": true,
	"Public":            true,
	"PublicUnwrapped":   true,
}

// readPermissions are the permissions that mean "may look", and must therefore
// never be what stands between a caller and a write. ⚠️ Kept here rather than
// imported from internal/api/middleware: archcheck is syntactic and standard
// library only (see the package comment in main.go), so it reads the names, not
// the values. Adding a Perm*Read* constant without adding it here makes this
// check quietly narrower — which is why the list is short and named after the
// convention rather than derived from it.
var readPermissions = map[string]bool{
	"PermReadBudgets":     true,
	"PermReadSigners":     true,
	"PermReadPresets":     true,
	"PermReadTemplates":   true,
	"PermReadHDWallets":   true,
	"PermReadAudit":       true,
	"PermReadACLs":        true,
	"PermReadMetrics":     true,
	"PermListRules":       true,
	"PermListOwnRequests": true,
	"PermListAllRequests": true,
}

var mutatingMethods = []string{"POST ", "PUT ", "PATCH ", "DELETE "}

// routeReg is one registration call site, as far as syntax can see it.
type routeReg struct {
	file    *goFile
	line    int
	ctor    string // Permitted / Public / AuthenticatedOnly / PublicUnwrapped
	mode    string // the baseline spelling: permitted / public / authenticated-only / public-unwrapped
	pattern string // resolved, "*" marking a part that is not a literal
	exact   bool   // whether pattern resolved completely
	perm    string // Perm* identifier, for ctor == Permitted
	reason  string // resolved reason, for the exemption ctors
	hasReas bool   // whether the reason resolved to a literal at all
}

// checkRouteAuth is the hard rule: zero baseline. Everything it reports is a
// hole in the mechanism itself rather than a route-level judgement, so there is
// nothing here to be traded off against a schedule.
func checkRouteAuth(r *repo) ([]finding, error) {
	var out []finding
	for _, f := range apiFiles(r) {
		vals := stringValues(f)

		// ⛔ ① Reaching the mux without going through the entry point.
		for _, decl := range f.File.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			isEntryPoint := recvTypeName(fd) == "Router" && fd.Name.Name == "handle"
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
					return true
				}
				recv := exprString(sel.X)
				onMux := recv == "mux" || strings.HasSuffix(recv, ".mux")
				onDefault := recv == "http"
				if !onMux && !onDefault {
					return true
				}
				if onMux && isEntryPoint {
					return true // the one sanctioned call
				}
				out = append(out, finding{
					Check: "route-auth",
					Key:   fmt.Sprintf("%s:%s.%s:mux-bypass", f.Path, recvTypeName(fd), fd.Name.Name),
					Path:  f.Path,
					Line:  f.Fset.Position(call.Pos()).Line,
					Msg: fmt.Sprintf("%s.%s registers a route directly — it never reaches the authorization table, so no exemption names it and nothing can notice it has no permission",
						recv, sel.Sel.Name),
				})
				return true
			})
		}

		// ⛔ ② A RouteAuth built as a composite literal sidesteps the
		// constructors, which are the only things that make a reason mandatory.
		if f.Path != "internal/api/route_auth.go" {
			ast.Inspect(f.File, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || exprString(lit.Type) != "RouteAuth" {
					return true
				}
				out = append(out, finding{
					Check: "route-auth",
					Key:   fmt.Sprintf("%s:%d:routeauth-literal", f.Path, f.Fset.Position(lit.Pos()).Line),
					Path:  f.Path,
					Line:  f.Fset.Position(lit.Pos()).Line,
					Msg:   "RouteAuth built as a composite literal — that is how a route ends up with no decision and no reason; use Permitted / AuthenticatedOnly / Public / PublicUnwrapped",
				})
				return true
			})
		}

		regs, stray := routeRegs(f, vals)

		// ⛔ ③ A constructor called somewhere other than a registration
		// argument. Binding one to a variable first would hide the route from
		// ④ and from the exemption list, and the hiding would be silent.
		for _, s := range stray {
			out = append(out, finding{
				Check: "route-auth",
				Key:   fmt.Sprintf("%s:%d:stray-ctor", f.Path, s.line),
				Path:  f.Path,
				Line:  s.line,
				Msg: fmt.Sprintf("%s(...) is not the second argument of a Handle/handle call — write the decision inline at the registration, otherwise the route is invisible to the exemption list",
					s.ctor),
			})
		}

		for _, reg := range regs {
			if !routeAuthCtors[reg.ctor] {
				continue // permitted: the permission is the justification
			}
			// ⛔ ④ 没有理由的豁免等于关掉检查.
			if !reg.hasReas || strings.TrimSpace(reg.reason) == "" {
				out = append(out, finding{
					Check: "route-auth",
					Key:   fmt.Sprintf("%s:%d:no-reason", f.Path, reg.line),
					Path:  f.Path,
					Line:  reg.line,
					Msg: fmt.Sprintf("route %q is exempted by %s(...) with no written reason — an exemption without one is indistinguishable from a route somebody forgot",
						reg.pattern, reg.ctor),
				})
				continue
			}
			// ⛔ ⑤ An exemption the list cannot name is an exemption that never expires.
			if !reg.exact {
				out = append(out, finding{
					Check: "route-auth",
					Key:   fmt.Sprintf("%s:%d:unresolvable-pattern", f.Path, reg.line),
					Path:  f.Path,
					Line:  reg.line,
					Msg:   "an exempt route's pattern must be a string literal, otherwise the exemption baseline cannot name it and cannot go red when the route changes",
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// checkRouteAuthExempt is the exemption list itself, and it is a ratchet in
// both directions on purpose. Each of the three ways an exemption rots is one
// of the two ratchet directions:
//
//   - a new route with no permission → a key the baseline does not have → red
//   - the route was deleted → a baseline key with nothing behind it → red
//   - the route now has a permission → same → red, and the line must go, or it
//     would not go red the next time that route loses its permission
//
// The reason lives at the call site rather than in the baseline: it belongs
// where the person changing the route will read it. The baseline names the
// route; ⛔ do not treat its comments as the authority.
func checkRouteAuthExempt(r *repo) ([]finding, error) {
	var out []finding
	for _, f := range apiFiles(r) {
		regs, _ := routeRegs(f, stringValues(f))
		for _, reg := range regs {
			if !routeAuthCtors[reg.ctor] {
				continue
			}
			out = append(out, finding{
				Check: "route-auth-exempt",
				Key:   reg.mode + " " + reg.pattern,
				Path:  f.Path,
				Line:  reg.line,
				Msg:   "route carries no permission — " + firstSentence(reg.reason),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// checkRouteMutatingPerm is the property the old route_permissions_test.go
// claimed and never had: no route that changes state is gated on a permission
// that only means "may look".
//
// ⚠️ It is a ratchet, not a hard rule, and the baseline is not a wish list —
// each entry is a route where the real decision is resource-scoped (does this
// caller own *this* signer?) and the route-level permission is only the outer
// door. Read the entry's reason before assuming it is debt.
//
// ⛔ This check does not know what a route *should* be gated on, and neither
// does anything else here. Changing a permission is a per-route security
// decision: too strict shows up in e2e immediately, too loose ships silently.
func checkRouteMutatingPerm(r *repo) ([]finding, error) {
	var out []finding
	for _, f := range apiFiles(r) {
		regs, _ := routeRegs(f, stringValues(f))
		for _, reg := range regs {
			if reg.ctor != "Permitted" || !isMutatingPattern(reg.pattern) || !readPermissions[reg.perm] {
				continue
			}
			out = append(out, finding{
				Check: "route-mutating-perm",
				Key:   reg.pattern,
				Path:  f.Path,
				Line:  reg.line,
				Msg:   fmt.Sprintf("mutating route gated on the read permission %s", reg.perm),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func apiFiles(r *repo) []*goFile {
	const scope = "internal/api"
	var out []*goFile
	for _, f := range r.Files {
		if f.Pkg == scope || strings.HasPrefix(f.Pkg, scope+"/") {
			out = append(out, f)
		}
	}
	return out
}

func isMutatingPattern(p string) bool {
	for _, m := range mutatingMethods {
		if strings.HasPrefix(p, m) {
			return true
		}
	}
	return false
}

// routeRegs finds every `X.Handle(pattern, <ctor>(...), h)` in a file, plus the
// constructor calls that appear anywhere else (which are reported, not used).
func routeRegs(f *goFile, vals map[string]string) (regs []routeReg, stray []routeReg) {
	claimed := map[token.Pos]bool{}

	ast.Inspect(f.File, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "handle" && sel.Sel.Name != "Handle") {
			return true
		}
		inner, ok := call.Args[1].(*ast.CallExpr)
		if !ok {
			return true
		}
		ctor, ok := ctorName(inner.Fun)
		if !ok {
			return true
		}
		claimed[inner.Pos()] = true

		reg := routeReg{
			file: f,
			line: f.Fset.Position(call.Pos()).Line,
			ctor: ctor,
			mode: modeName(ctor),
		}
		reg.pattern, reg.exact = resolveString(call.Args[0], vals)
		if len(inner.Args) == 1 {
			if routeAuthCtors[ctor] {
				reg.reason, reg.hasReas = resolveString(inner.Args[0], vals)
			} else {
				reg.perm = permName(inner.Args[0])
			}
		}
		regs = append(regs, reg)
		return true
	})

	ast.Inspect(f.File, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || claimed[call.Pos()] {
			return true
		}
		ctor, ok := ctorName(call.Fun)
		if !ok || !routeAuthCtors[ctor] {
			return true
		}
		// The constructors' own definitions and the tests' fixtures are calls
		// too; only route_auth.go declares them, and it is skipped here.
		if f.Path == "internal/api/route_auth.go" {
			return true
		}
		stray = append(stray, routeReg{file: f, line: f.Fset.Position(call.Pos()).Line, ctor: ctor})
		return true
	})
	return regs, stray
}

func ctorName(e ast.Expr) (string, bool) {
	switch t := e.(type) {
	case *ast.Ident:
		if _, ok := routeAuthCtors[t.Name]; ok {
			return t.Name, true
		}
	case *ast.SelectorExpr:
		if exprString(t.X) == "api" {
			if _, ok := routeAuthCtors[t.Sel.Name]; ok {
				return t.Sel.Name, true
			}
		}
	}
	return "", false
}

func modeName(ctor string) string {
	switch ctor {
	case "AuthenticatedOnly":
		return "authenticated-only"
	case "Public":
		return "public"
	case "PublicUnwrapped":
		return "public-unwrapped"
	default:
		return "permitted"
	}
}

// permName renders middleware.PermFoo / PermFoo as "PermFoo".
func permName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// stringValues maps identifiers to the string constants they hold, so a reason
// shared by four routes can be written once.
//
// ⚠️ Deliberately scope-blind: it collects every `x = "..."` and `const x =
// "..."` in the file into one namespace. Two different locals with the same
// name and different strings would resolve to whichever came last. That is
// acceptable for what this reads — a reason and a route pattern — and the
// alternative is a type checker, which main.go's package comment explains this
// tool declines to be.
func stringValues(f *goFile) map[string]string {
	out := map[string]string{}
	// Two passes: a value may be defined after its use in source order.
	for i := 0; i < 2; i++ {
		ast.Inspect(f.File, func(n ast.Node) bool {
			switch t := n.(type) {
			case *ast.ValueSpec:
				for i, name := range t.Names {
					if i < len(t.Values) {
						if s, ok := resolveString(t.Values[i], out); ok {
							out[name.Name] = s
						}
					}
				}
			case *ast.AssignStmt:
				if len(t.Lhs) != 1 || len(t.Rhs) != 1 {
					return true
				}
				id, ok := t.Lhs[0].(*ast.Ident)
				if !ok {
					return true
				}
				if s, ok := resolveString(t.Rhs[0], out); ok {
					out[id.Name] = s
				}
			}
			return true
		})
	}
	return out
}

// resolveString renders a string expression. The bool is whether it resolved
// completely; a partially resolved pattern comes back with "*" where the
// unknown part was, which is what makes the four `"…/"+action` signer
// registrations readable as one baseline key.
func resolveString(e ast.Expr, vals map[string]string) (string, bool) {
	switch t := e.(type) {
	case *ast.BasicLit:
		if t.Kind != token.STRING {
			return "*", false
		}
		s, err := strconv.Unquote(t.Value)
		if err != nil {
			return "*", false
		}
		return s, true
	case *ast.Ident:
		if s, ok := vals[t.Name]; ok {
			return s, true
		}
		return "*", false
	case *ast.BinaryExpr:
		if t.Op != token.ADD {
			return "*", false
		}
		l, lok := resolveString(t.X, vals)
		rr, rok := resolveString(t.Y, vals)
		return l + rr, lok && rok
	case *ast.ParenExpr:
		return resolveString(t.X, vals)
	}
	return "*", false
}

// firstSentence trims a reason down to what fits in a one-line finding. The
// whole reason stays at the call site; this is a pointer to it.
func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	for _, end := range []string{". ", "。", "; "} {
		if i := strings.Index(s, end); i > 0 && i < 160 {
			return s[:i+1]
		}
	}
	if len(s) > 160 {
		return strings.TrimSpace(s[:160]) + "…"
	}
	return s
}
