package main

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
)

// ---------- layers: the dependency rule ----------
//
// One finding per (importing package → imported package) pair, not per import
// statement: the unit a person fixes is the edge, and keying on the edge keeps
// the baseline stable when a file moves.
func checkLayers(r *repo) ([]finding, error) {
	type edge struct{ from, to string }
	seen := map[edge]finding{}

	for _, f := range r.Files {
		from := layerOf(f.Pkg)
		if from == nil {
			continue // unclassified: reported by -unclassified, never failed on
		}
		allowed := map[string]bool{from.Name: true}
		for _, a := range from.MayImport {
			allowed[a] = true
		}
		for _, im := range f.Imports {
			if !strings.HasPrefix(im.Path, r.Module+"/") {
				continue // third party and stdlib are not layered here
			}
			toPkg := strings.TrimPrefix(im.Path, r.Module+"/")
			to := layerOf(toPkg)
			if to == nil || allowed[to.Name] {
				continue
			}
			e := edge{f.Pkg, toPkg}
			if _, dup := seen[e]; dup {
				continue
			}
			seen[e] = finding{
				Check: "layers",
				Key:   f.Pkg + " -> " + toPkg,
				Path:  f.Path,
				Line:  im.Line,
				Msg: fmt.Sprintf("%s (%s) imports %s (%s) — %s",
					f.Pkg, from.Name, toPkg, to.Name, from.Why),
			}
		}
	}

	out := make([]finding, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// ---------- frozen-settings: knobs captured at construction time ----------
//
// internal/settings/model.go promises settings become "effective without a
// daemon restart". A knob copied into a struct field is frozen at construction,
// so for that knob the promise is false and nothing says so.
//
// The check reads SecuritySnapshot's field list from the AST — not a hardcoded
// list — so renaming or adding a knob keeps the check honest. It then looks for
// struct fields elsewhere whose name matches one case-insensitively.
//
// ⚠️ Name matching is the weak link and it is deliberate: a knob reaches a
// handler as a plain bool/int/Duration, so the type carries no signal at all
// and the name is the only thing that does. It is scoped to internal/api to
// keep that heuristic somewhere the false-positive cost is low.
func checkFrozenSettings(r *repo) ([]finding, error) {
	knobs := map[string]string{} // lowercased -> canonical
	for _, f := range r.Files {
		if f.Pkg != "internal/settings" {
			continue
		}
		ast.Inspect(f.File, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "SecuritySnapshot" {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				for _, nm := range fld.Names {
					if nm.IsExported() {
						knobs[strings.ToLower(nm.Name)] = nm.Name
					}
				}
			}
			return false
		})
	}
	if len(knobs) == 0 {
		return nil, fmt.Errorf("could not read settings.SecuritySnapshot fields (renamed?)")
	}

	var out []finding
	for _, f := range r.Files {
		if !strings.HasPrefix(f.Pkg, "internal/api") {
			continue
		}
		ast.Inspect(f.File, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				for _, nm := range fld.Names {
					canon, isKnob := knobs[strings.ToLower(nm.Name)]
					if !isKnob {
						continue
					}
					// A knob arrives as a scalar. A field sharing the name but
					// holding a service object is a different thing wearing the
					// same word — RouterConfig.ApprovalGuard is the guard itself
					// (and the one knob that IS kept live, via
					// router.syncApprovalGuard), not a copy of the setting.
					// Flagging it would be the kind of near-miss that gets a
					// gate switched off.
					if !isKnobType(fld.Type) {
						continue
					}
					out = append(out, finding{
						Check: "frozen-settings",
						Key:   f.Pkg + "." + ts.Name.Name + "." + nm.Name,
						Path:  f.Path,
						Line:  f.Fset.Position(nm.Pos()).Line,
						Msg: fmt.Sprintf("%s.%s freezes settings.SecuritySnapshot.%s at construction time",
							ts.Name.Name, nm.Name, canon),
					})
				}
			}
			return true
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// ---------- respond-shape: one name, several argument orders ----------
//
// 48 per-handler write helpers exist under two argument orders each for
// writeJSON and writeError. Both compile — (any, int) and (int, any) — so
// swapping them ships an error body inside a 200 and no test has to notice.
//
// This reports the *minority* shapes: the majority one is the de-facto
// convention, and the fix is to make the others match before the whole set
// moves to a shared package.
func checkRespondShape(r *repo) ([]finding, error) {
	type site struct {
		file  string
		line  int
		recv  string
		shape string
	}
	byName := map[string][]site{}

	for _, f := range r.Files {
		if !strings.HasPrefix(f.Pkg, "internal/api") {
			continue
		}
		for _, decl := range f.File.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name == nil {
				continue
			}
			switch fd.Name.Name {
			case "writeJSON", "writeError", "writeHTTPError", "writeRPCError":
			default:
				continue
			}
			// ⚠️ Classify each parameter by ROLE, not by its exact type.
			// The property being enforced is the argument *order*: (w, body,
			// code) vs (w, code, body), both of which compile. Comparing exact
			// type strings instead reports a helper whose body parameter is a
			// concrete type rather than `any` — same order, different spelling —
			// and a gate that fires on a difference nobody needs to fix is one
			// that gets switched off. rpc_proxy.go's writeJSON(w, jsonRPCEnvelope,
			// int) is exactly that case.
			var params []string
			for _, p := range fd.Type.Params.List {
				role := paramRole(exprString(p.Type))
				n := len(p.Names)
				if n == 0 {
					n = 1
				}
				for i := 0; i < n; i++ {
					params = append(params, role)
				}
			}
			byName[fd.Name.Name] = append(byName[fd.Name.Name], site{
				file:  f.Path,
				line:  f.Fset.Position(fd.Pos()).Line,
				recv:  recvTypeName(fd),
				shape: strings.Join(params, ","),
			})
		}
	}

	var out []finding
	for name, sites := range byName {
		counts := map[string]int{}
		for _, s := range sites {
			counts[s.shape]++
		}
		if len(counts) < 2 {
			continue
		}
		major, majorN := "", -1
		for shape, n := range counts {
			if n > majorN || (n == majorN && shape < major) {
				major, majorN = shape, n
			}
		}
		for _, s := range sites {
			if s.shape == major {
				continue
			}
			out = append(out, finding{
				Check: "respond-shape",
				Key:   s.file + ":" + s.recv + "." + name,
				Path:  s.file,
				Line:  s.line,
				Msg: fmt.Sprintf("%s.%s(%s) — %d others use (%s); both compile, so a swapped call ships an error body with a 200",
					s.recv, name, s.shape, majorN, major),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func recvTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	return strings.TrimPrefix(exprString(fd.Recv.List[0].Type), "*")
}

// exprString renders a type expression compactly. It only needs to be stable
// and readable, not to round-trip.
func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprString(t.Elt)
	case *ast.MapType:
		return "map[" + exprString(t.Key) + "]" + exprString(t.Value)
	case *ast.InterfaceType:
		if t.Methods == nil || len(t.Methods.List) == 0 {
			return "any"
		}
		return "interface{...}"
	case *ast.Ellipsis:
		return "..." + exprString(t.Elt)
	case *ast.FuncType:
		return "func"
	default:
		return "?"
	}
}

// isKnobType reports whether a struct field's type is one a settings knob can
// take: bool, an integer, a string, a duration, or a list of strings.
// Anything else (a pointer to a service, an interface, a func) is a different
// concept that happens to share a name.
func isKnobType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		switch t.Name {
		case "bool", "string",
			"int", "int8", "int16", "int32", "int64",
			"uint", "uint8", "uint16", "uint32", "uint64",
			"float32", "float64":
			return true
		}
		return false
	case *ast.SelectorExpr:
		return exprString(t) == "time.Duration"
	case *ast.StarExpr:
		// *bool / *int are how "unset" is spelled in this config.
		return isKnobType(t.X)
	case *ast.ArrayType:
		return isKnobType(t.Elt)
	default:
		return false
	}
}

// ---------- rule-write: who can write a spending authorization ----------
//
// A rule is a spending authorization: it decides which transactions get signed
// without a human. So "who can write to the rules table" is the property most
// worth pinning, and mandatory validation currently lives in
// internal/api/handler/validation_mandatory.go — an HTTP-layer policy, not a
// domain invariant, which every non-HTTP path bypasses.
//
// This replaces a grep gate that matched the *text* `storage.RuleRepository`.
// That gate flagged this very file for mentioning the type inside a comment —
// the same defect as the Solidity ratchet counting comments. Here the type name
// is read from declarations only, so prose cannot trip it and cannot hide in it.
//
// ⚠️ Honest about its limit: this is file-local. It knows a field or parameter
// was *declared* with a rule-repo type and that `.Create(`/`.Update(` is called
// on that identifier somewhere in the same file. It is not a call graph — a
// repo passed through three helpers in different files is not tracked, which is
// why the holder list, not the call site, is what the baseline pins.
func checkRuleWrite(r *repo) ([]finding, error) {
	const repoType = "storage.RuleRepository"

	var out []finding
	for _, f := range r.Files {
		if strings.HasPrefix(f.Pkg, "internal/storage") {
			continue // the implementation is allowed to be the implementation
		}
		holders := map[string]bool{} // identifiers typed as a rule repo
		constructs := false

		ast.Inspect(f.File, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Field: // struct fields, params, results
				if exprString(x.Type) == repoType || strings.HasSuffix(exprString(x.Type), "GormRuleRepository") {
					for _, nm := range x.Names {
						holders[nm.Name] = true
					}
					if len(x.Names) == 0 {
						holders["_embedded"] = true
					}
				}
			case *ast.ValueSpec: // var x storage.RuleRepository
				if x.Type != nil && exprString(x.Type) == repoType {
					for _, nm := range x.Names {
						holders[nm.Name] = true
					}
				}
			case *ast.CallExpr:
				if exprString(x.Fun) == "storage.NewGormRuleRepository" {
					constructs = true
				}
			}
			return true
		})

		if len(holders) == 0 && !constructs {
			continue
		}

		writes := false
		ast.Inspect(f.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Create" && sel.Sel.Name != "Update") {
				return true
			}
			// x.Create(...) where x is a tracked identifier, or h.ruleRepo.Create(...)
			switch base := sel.X.(type) {
			case *ast.Ident:
				if holders[base.Name] {
					writes = true
				}
			case *ast.SelectorExpr:
				if holders[base.Sel.Name] {
					writes = true
				}
			}
			return true
		})

		// The chokepoint is rule.ValidateRuleForWrite (see internal/core/rule/writer.go).
		// ruleconfig.ValidateRuleConfig still counts: it is what the chokepoint
		// calls, and the HTTP handlers that validate a request body before
		// building a rule legitimately call it directly.
		src := sourceOf(f)
		// UpdateMetadata counts as well: it is the writer's documented way of
		// saying "this write carries no config", and saying it in code is what
		// distinguishes a deliberate exception from a forgotten check. See
		// internal/core/rule/writer.go for why disabling a malformed rule must
		// not require the rule to be valid.
		validates := strings.Contains(src, "ValidateRuleForWrite") ||
			strings.Contains(src, "UpdateMetadata(") ||
			strings.Contains(src, "ruleconfig.ValidateRuleConfig")

		key := f.Path
		msg := "holds a rule-repo handle"
		if writes && !validates {
			key = f.Path + " [writes-unvalidated]"
			msg = "writes through a rule repo without ruleconfig.ValidateRuleConfig in the same file"
		}
		out = append(out, finding{
			Check: "rule-write",
			Key:   key,
			Path:  f.Path,
			Line:  1,
			Msg:   msg,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// paramRole reduces a parameter type to the role it plays in a write helper,
// so that two helpers differing only in how the body is spelled compare equal.
func paramRole(t string) string {
	switch t {
	case "http.ResponseWriter":
		return "w"
	case "int":
		return "code"
	case "string":
		return "msg"
	default:
		return "body"
	}
}
