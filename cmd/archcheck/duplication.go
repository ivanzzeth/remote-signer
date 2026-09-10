package main

import (
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"regexp"
	"sort"
	"strings"
)

// ---------- near-duplicate functions ----------
//
// This check exists because "the same thing written twice" is how every bug in
// this repo's recent history got in, and because counting it makes "same
// behaviour, less code" an invariant rather than an intention.
//
// What it found on the run that introduced it:
//
//   - AddDelegationTargets existed three times. Two copies were byte-for-byte;
//     the third read an unparseable rule config as "delegates to nothing", so
//     the isolated engine validated a rule without its delegation chain and
//     reported a pass.
//   - PresetRegistry.Sync and TemplateRegistry.Sync differed in a loop variable
//     name and a log noun — two copies of a step that deletes catalogue rows.
//   - The four Solidity script shapes each had their own generator and
//     evaluator, and the two typed-data ones each spelled out the same seven
//     EIP-712 domain bindings.
//
// ⚠️ Similar is not the same as duplicated. Two functions can look alike and
// mean different things, and merging those makes the code worse. The baseline
// is where such a pair goes, with the reason. What the ratchet forbids is the
// number growing.

const (
	// dupMinLines is how long a function must be before a near-twin is
	// interesting. Short functions repeat legitimately — getters, guards,
	// three-line adapters — and flagging them buries the real pairs.
	dupMinLines = 30
	// dupThreshold is the similarity at which two functions are near-twins.
	// ⚠️ Measured on normalized shape, not text: identifiers and string
	// literals are erased first, so a copy that renamed its loop variable
	// still scores 100%.
	dupThreshold = 0.88
	// dupLengthSkew prefilters pairs too different in size to reach the
	// threshold, which is what keeps this an O(n) walk in practice.
	dupLengthSkew = 0.4
)

type dupFunc struct {
	Path  string
	Name  string
	Line  int
	Shape []string
	Set   map[string]bool
}

func checkDuplication(r *repo) ([]finding, error) {
	var fns []dupFunc

	for _, f := range r.Files {
		for _, decl := range f.File.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			shape := normalizeShape(f.Fset, fd)
			if len(shape) < dupMinLines {
				continue
			}
			set := make(map[string]bool, len(shape))
			for _, l := range shape {
				set[l] = true
			}
			fns = append(fns, dupFunc{
				Path:  f.Path,
				Name:  funcName(fd),
				Line:  f.Fset.Position(fd.Pos()).Line,
				Shape: shape,
				Set:   set,
			})
		}
	}

	sort.Slice(fns, func(i, j int) bool {
		if fns[i].Path != fns[j].Path {
			return fns[i].Path < fns[j].Path
		}
		return fns[i].Line < fns[j].Line
	})

	var out []finding
	for i := 0; i < len(fns); i++ {
		for j := i + 1; j < len(fns); j++ {
			a, b := fns[i], fns[j]
			la, lb := len(a.Shape), len(b.Shape)
			if absInt(la-lb) > int(float64(maxInt(la, lb))*dupLengthSkew) {
				continue
			}
			if jaccard(a.Set, b.Set) < dupThreshold-0.15 {
				continue // cheap reject before the quadratic compare
			}
			ratio := lcsRatio(a.Shape, b.Shape)
			if ratio < dupThreshold {
				continue
			}
			out = append(out, finding{
				Check: "duplication",
				Key:   fmt.Sprintf("%s:%s <-> %s:%s", a.Path, a.Name, b.Path, b.Name),
				Path:  a.Path,
				Line:  a.Line,
				Msg:   fmt.Sprintf("%.0f%% identical in shape to %s:%d %s (%d and %d lines)", ratio*100, b.Path, b.Line, b.Name, la, lb),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		var sb strings.Builder
		_ = printer.Fprint(&sb, token.NewFileSet(), fd.Recv.List[0].Type)
		return "(" + sb.String() + ")." + fd.Name.Name
	}
	return fd.Name.Name
}

var (
	dupStringLit = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	dupIdent     = regexp.MustCompile(`\b[a-z][A-Za-z0-9_]*\b`)
	dupNumber    = regexp.MustCompile(`\b\d+\b`)
)

// normalizeShape renders a function body and erases everything a copy is free
// to rename: identifiers, string literals, numbers, comments and blank lines.
// What is left is control flow and call structure — the thing two copies share.
func normalizeShape(fset *token.FileSet, fd *ast.FuncDecl) []string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, fd.Body); err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(sb.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		line = dupStringLit.ReplaceAllString(line, `"S"`)
		line = dupNumber.ReplaceAllString(line, "N")
		line = dupIdent.ReplaceAllString(line, "v")
		out = append(out, line)
	}
	return out
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	return float64(inter) / float64(len(a)+len(b)-inter)
}

// lcsRatio is 2*LCS/(len(a)+len(b)) — the same measure difflib reports.
func lcsRatio(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			if a[i-1] == b[j-1] {
				cur[j] = prev[j-1] + 1
			} else {
				cur[j] = maxInt(prev[j], cur[j-1])
			}
		}
		prev, cur = cur, prev
	}
	return 2 * float64(prev[len(b)]) / float64(len(a)+len(b))
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
