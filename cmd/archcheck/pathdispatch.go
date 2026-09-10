package main

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
)

// ---------- handler-path-dispatch: handlers that route themselves ----------
//
// The repo is going to decompose its prefix-dispatching handlers into real Go
// 1.22+ method+wildcard mux patterns, so that an OpenAPI spec can be generated
// from per-endpoint annotations. This gate is what makes that decomposition
// monotonic: fix one handler, the baseline shrinks; regress, it goes red.
//
// # What is wrong today
//
// One mux pattern is registered and the handler behind it fans out into many
// logical endpoints by hand, from the request path:
//
//	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/rules")   // rule.go:182
//	...                                                            // 12 endpoints
//
// internal/api/handler/evm/rule.go:171-289 serves twelve endpoints that way;
// wallet.go serves eight, settings.go eighteen. ⛔ A `@Router`/`@Summary`
// annotation on such a function can only be a guess — there is no one path and
// no one method to annotate. That is why the decomposition has to happen before
// the spec, and why this gate measures the *handler* side.
//
// ⭐ It has to be the handler side. `router.go:437,445,446` already register
// `{address}` wildcards, and `grep -rn "PathValue" internal/` returns 0
// repo-wide: the wildcards are decorative, because the handlers still slice
// `r.URL.Path` themselves. A gate counting wildcard registrations would already
// read as partly fixed while nothing behind them had changed.
//
// # Scope: internal/api/handler/** only
//
// ⛔ internal/api/middleware/ is deliberately out of scope, and this was
// verified rather than assumed. Every read there is one of two legitimate
// shapes, neither of which decomposition removes:
//
//   - middleware/auth.go:97-100 signs the request. It must use EscapedPath()
//     over the exact bytes the client signed — preset ids contain '/', the JS
//     SDK sends them as %2F, and PathValue() hands back a *decoded* segment, so
//     a "fixed" middleware would reject every such request with a 401.
//   - auth/rbac/ratelimit/ipwhitelist/logging record the request line in the
//     audit log (auth.go:162, rbac.go:207, ratelimit.go:62, ipwhitelist.go:233,
//     logging.go:65). An audit entry has to say which path was asked for; that
//     is the whole path, not whichever segment one route happened to name.
//
// Also out of scope by the same prefix rule and for the same kind of reason:
// internal/api/router.go (the SPA catch-all at :663 legitimately inspects the
// path it did not route) and internal/web/handler.go (static file serving).
//
// ⚠️ Not exempted, though the proposal floats it: handler/evm/rpc_proxy.go:123.
// §2.6 calls it unsafe to *touch*, which is a sequencing judgement about the
// decomposition PRs; its `TrimPrefix(r.URL.Path, "/api/v1/evm/rpc/")` is still
// exactly the read PathValue replaces. Exempting it would hide a fixable entry
// behind a note about scheduling. It sits in the baseline instead.
//
// ⚠️ Also not exempted: the handlers whose only read logs the path
// (sign.go:108, approval.go:100). A criterion that tried to tell "just a log"
// from "dispatch" would have to guess at call context, and the guess is
// defeated by assigning to a local first. Those entries carry their reason in
// the baseline file, which is what this repo does with a finding that is real
// but not the interesting kind.
//
// # The criterion
//
// A function whose body reads Path / RawPath / EscapedPath() off an
// *http.Request's URL, or reads RequestURI off the request itself.
//
// ⚠️ RawPath and RequestURI are not in the original proposal. They are here
// because without them the gate is defeated by a one-word rename — the same
// string, spelled differently — and a criterion that loose is worse than none:
// it makes people think someone is watching.
//
// ⚠️ The request identifier is resolved by *declared type*, not by being named
// `r`. Same approach as checkRuleWrite: file-local, declaration-only. `r` is
// also the conventional receiver name for *Router elsewhere in internal/api, so
// matching the name would be matching the wrong thing half the time. The limit
// is the usual one — a request stashed in a struct field and read three calls
// later is not tracked; this is syntactic, not a call graph.
func checkHandlerPathDispatch(r *repo) ([]finding, error) {
	const scope = "internal/api/handler"

	var out []finding
	for _, f := range r.Files {
		if f.Pkg != scope && !strings.HasPrefix(f.Pkg, scope+"/") {
			continue
		}
		for _, decl := range f.File.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			reqs := requestIdents(fd)
			if len(reqs) == 0 {
				continue
			}

			members := map[string]bool{}
			count := 0
			line := 0
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				var member string
				switch sel.Sel.Name {
				case "Path", "RawPath", "EscapedPath":
					// req.URL.Path / req.URL.EscapedPath()
					inner, ok := sel.X.(*ast.SelectorExpr)
					if !ok || inner.Sel.Name != "URL" {
						return true
					}
					id, ok := inner.X.(*ast.Ident)
					if !ok || !reqs[id.Name] {
						return true
					}
					member = "URL." + sel.Sel.Name
				case "RequestURI":
					id, ok := sel.X.(*ast.Ident)
					if !ok || !reqs[id.Name] {
						return true
					}
					member = "RequestURI"
				default:
					return true
				}
				members[member] = true
				count++
				if pos := f.Fset.Position(sel.Pos()).Line; line == 0 || pos < line {
					line = pos
				}
				return true
			})
			if count == 0 {
				continue
			}

			names := make([]string, 0, len(members))
			for m := range members {
				names = append(names, m)
			}
			sort.Strings(names)
			out = append(out, finding{
				Check: "handler-path-dispatch",
				Key:   pathDispatchKey(f.Pkg, fd),
				Path:  f.Path,
				Line:  line,
				Msg: fmt.Sprintf("reads %s (%d×) — the handler is routing itself, so one mux pattern hides several endpoints and none of them can carry an honest @Router annotation",
					strings.Join(names, "/"), count),
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// pathDispatchKey is <pkg>.<Recv>.<FuncName>, with no line number: the baseline
// has to survive edits above the function. The receiver component is dropped
// for a plain function rather than left as an empty segment.
func pathDispatchKey(pkg string, fd *ast.FuncDecl) string {
	if recv := recvTypeName(fd); recv != "" {
		return pkg + "." + recv + "." + fd.Name.Name
	}
	return pkg + "." + fd.Name.Name
}

// requestIdents returns the identifiers inside fd that were *declared* as
// *http.Request: the function's own parameters, its receiver, and the
// parameters of any function literal in its body (handlers hand closures to
// mux.HandleFunc, and a read inside one belongs to the enclosing function as
// far as the person fixing it is concerned).
func requestIdents(fd *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	collect := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, p := range fl.List {
			if exprString(p.Type) != "*http.Request" {
				continue
			}
			for _, nm := range p.Names {
				out[nm.Name] = true
			}
		}
	}
	collect(fd.Recv)
	collect(fd.Type.Params)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if fl, ok := n.(*ast.FuncLit); ok {
			collect(fl.Type.Params)
		}
		return true
	})
	return out
}
