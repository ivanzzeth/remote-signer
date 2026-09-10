// Command archcheck is this repository's AST-based architecture checker.
//
// Why an AST tool and not grep: the constraints worth enforcing here are about
// *structure* — which layer imports which, what shape a struct field has, how
// many argument orders one helper name has — and grep can only see text. The
// grep-based gates under scripts/arch/ each carry a note about a case they got
// wrong; every one of those was a text/structure mismatch. Two examples this
// tool exists to avoid repeating:
//
//   - The Solidity ratchet counted `evm_solidity_expression` occurrences and 15
//     of the 88 were comments saying the template does NOT use it.
//   - The test-helper gate skipped files by the `_test` substring while the Go
//     compiler decides by the `_test.go` suffix — a blind spot the gate could
//     not see into.
//
// Why not golangci-lint/depguard: `make check` is a seconds-scale gate and the
// repo's public SDK lives in the same module, so an extra direct dependency is
// not free. This uses only go/ast + go/parser from the standard library;
// parsing the whole repo takes well under a second.
//
// ⚠️ Deliberate limitation: this is syntactic, not type-checked. It reads
// imports, declarations and selector expressions, and resolves types only
// within a single file (a field declared `foo storage.RuleRepository` is
// tracked as that type inside its own file). Where a check would need a call
// graph it says so instead of guessing.
//
// Usage:
//
//	archcheck [-baseline dir] [-unclassified] [check...]
//
// With no check names it runs all of them.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// finding is one violation. Path/Line locate it; Key is what the baseline
// matches on, so it must be stable across unrelated edits (no line numbers).
type finding struct {
	Check string
	Key   string
	Path  string
	Line  int
	Msg   string
}

type checkFunc func(*repo) ([]finding, error)

type checkDef struct {
	Name     string
	Baseline string // file under the baseline dir; empty = hard rule, must be zero
	Hint     string
	Run      checkFunc

	// Record marks a baseline that is a record of current truth rather than a
	// list of debt. ⚠️ It changes only what reportRatchet *prints*: the two
	// boilerplate lines ("don't just add it to the baseline", "delete those
	// lines, the ratchet only goes down") are correct advice for a debt list and
	// actively wrong for a record — there, the right move on a moved key is to
	// edit the line, and the baseline is not supposed to shrink at all.
	Record bool
}

var checks = []checkDef{
	{
		Name:     "layers",
		Baseline: "layers.txt",
		Hint:     "Depend inwards. If the inner layer needs something from the outer one, it declares an interface and the outer one implements it.",
		Run:      checkLayers,
	},
	{
		Name:     "frozen-settings",
		Baseline: "frozen-settings.txt",
		Hint:     "Read settingsMgr.Security().<field> on the request path instead of storing the knob in a struct field.",
		Run:      checkFrozenSettings,
	},
	{
		Name:     "rule-write",
		Baseline: "rule-write.txt",
		Hint:     "Go through an existing service (TemplateService / RuleHandler) rather than taking a bare repo handle; validate inside the writer, not at the HTTP edge.",
		Run:      checkRuleWrite,
	},
	{
		Name:     "duplication",
		Baseline: "duplication.txt",
		Hint:     "Give the shape one implementation and let both callers use it. ⚠️ Similar is not duplicated — a pair that only looks alike belongs in the baseline with the reason, not merged.",
		Run:      checkDuplication,
	},
	{
		Name:     "rule-type-table",
		Baseline: "rule-type-table.txt",
		Hint:     "Add the constant to types.ruleTypes. ⛔ This baseline stays empty — it is a two-line invariant, not debt.",
		Run:      checkRuleTypeTable,
	},
	{
		Name:     "engine-dispatch",
		Baseline: "engine-dispatch.txt",
		Hint:     "Let the engine answer the question — a RuleValidator interface and a registry, the way RuleEvaluator already works for evaluation. ⛔ Never by removing an engine.",
		Run:      checkEngineDispatch,
	},
	{
		Name:     "mirror-structs",
		Baseline: "mirror-structs.txt",
		Hint:     "Give the format one struct and let the other packages alias it (`type X = pkg.X`). A mirror that is merely brought back in step drifts again the next time a field is added.",
		Run:      checkMirrorStructs,
	},
	{
		Name:     "handler-path-dispatch",
		Baseline: "handler-path-dispatch.txt",
		Hint:     "Register the sub-path as its own mux pattern (Go 1.22 `POST /api/v1/evm/rules/{id}/approve`) and read `r.PathValue(\"id\")`. ⛔ A handler still slicing `r.URL.Path` fans one pattern out into many logical endpoints — handler/evm/rule.go serves 12 behind one — so a per-endpoint OpenAPI annotation on it can only be a guess. Fix one handler and this baseline shrinks by a line.",
		Run:      checkHandlerPathDispatch,
	},
	{
		Name:     "route-auth",
		Baseline: "", // hard rule: a hole in the mechanism is not debt to be scheduled
		Hint:     "Register through (*Router).handle with Permitted(perm) — or, when the route genuinely carries no permission, AuthenticatedOnly/Public/PublicUnwrapped with a written reason. ⛔ 没有理由的豁免等于关掉检查:an exemption nobody can argue with is the same as no check at all.",
		Run:      checkRouteAuth,
	},
	{
		Name:     "route-auth-exempt",
		Baseline: "route-auth-exemptions.txt",
		Hint:     "Every route that declares no permission is listed here with its reason at the call site. ⛔ Adding a line means adding an endpoint nobody has to hold a permission for — say why in the constructor first. Removing one is the good direction: a route that gained a permission, or stopped existing, must lose its line or the list stops going red when it matters.",
		Run:      checkRouteAuthExempt,
	},
	{
		Name:     "route-mutating-perm",
		Baseline: "route-mutating-perm.txt",
		Hint:     "A route that changes state must not be reachable on a permission that only means \"may look\". ⚠️ Where the real check is resource-scoped (does this caller own *this* signer?), the route-level permission is only the outer door — those entries are in the baseline with the reason.",
		Run:      checkRouteMutatingPerm,
	},
	{
		Name:     "route-perm-binding",
		Baseline: "route-perm-bindings.txt",
		Hint:     "A route's permission moved. ⛔ This baseline is not debt and is not supposed to shrink — it is the record of which permission every permitted route is gated on, one line per route. If the move is intended, edit the line: that edit *is* the re-approval, and it lands in the diff of a security-relevant file instead of nowhere.",
		Record:   true,
		Run:      checkRoutePermBinding,
	},
	{
		Name:     "respond-shape",
		Baseline: "respond-shape.txt",
		Hint:     "One argument order for all of them, then delete the per-handler copies in favour of a shared respond package.",
		Run:      checkRespondShape,
	},
}

func main() {
	baselineDir := flag.String("baseline", "scripts/lib/arch-baseline/ast", "directory holding baseline files")
	showUnclassified := flag.Bool("unclassified", false, "list packages that match no layer and exit")
	// ⚠️ -list prints the complete current finding set, which is what a baseline
	// file must contain. The normal output prints only what *differs* from the
	// baseline, and regenerating a baseline from that diff silently drops every
	// entry that was already in it.
	listOnly := flag.Bool("list", false, "print every current finding (baseline contents) and exit")
	flag.Parse()

	r, err := loadRepo(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "archcheck: %v\n", err)
		os.Exit(2)
	}

	if *showUnclassified {
		listUnclassified(r)
		return
	}

	if *listOnly {
		for _, c := range checks {
			if len(flag.Args()) > 0 && !contains(flag.Args(), c.Name) {
				continue
			}
			found, err := c.Run(r)
			if err != nil {
				fmt.Fprintf(os.Stderr, "archcheck %s: %v\n", c.Name, err)
				os.Exit(2)
			}
			seen := map[string]bool{}
			for _, f := range found {
				if seen[f.Key] {
					continue
				}
				seen[f.Key] = true
				fmt.Println(f.Key)
			}
		}
		return
	}

	only := map[string]bool{}
	for _, a := range flag.Args() {
		only[a] = true
	}

	failed := false
	for _, c := range checks {
		if len(only) > 0 && !only[c.Name] {
			continue
		}
		found, err := c.Run(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "archcheck %s: %v\n", c.Name, err)
			os.Exit(2)
		}
		if !reportRatchet(c, found, *baselineDir) {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// reportRatchet compares findings against the baseline and prints both
// directions: new violations, and baseline entries that no longer exist.
//
// ⚠️ The second direction is not optional. Without it a baseline only ever
// grows, entries stay in it after being fixed, and the next person reads them
// as "violations are allowed here" and copies the pattern.
func reportRatchet(c checkDef, found []finding, baselineDir string) bool {
	actual := map[string]finding{}
	keys := []string{}
	for _, f := range found {
		if _, seen := actual[f.Key]; !seen {
			keys = append(keys, f.Key)
		}
		actual[f.Key] = f
	}
	sort.Strings(keys)

	if c.Baseline == "" {
		if len(keys) == 0 {
			fmt.Printf("==> %s: ok\n", c.Name)
			return true
		}
		fmt.Printf("==> %s\n", c.Name)
		for _, k := range keys {
			f := actual[k]
			fmt.Fprintf(os.Stderr, "  ✗ %s:%d %s\n", f.Path, f.Line, f.Msg)
		}
		fmt.Fprintf(os.Stderr, "    改法:%s\n", c.Hint)
		return false
	}

	path := baselineDir + "/" + c.Baseline
	expected, err := readBaseline(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ %s: cannot read baseline %s: %v\n", c.Name, path, err)
		return false
	}

	var added, removed []string
	for _, k := range keys {
		if !expected[k] {
			added = append(added, k)
		}
	}
	for k := range expected {
		if _, ok := actual[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(removed)

	if len(added) == 0 && len(removed) == 0 {
		fmt.Printf("==> %s: ok (%d known)\n", c.Name, len(expected))
		return true
	}
	fmt.Printf("==> %s\n", c.Name)
	if len(added) > 0 {
		fmt.Fprintf(os.Stderr, "  ✗ 新增了基线之外的违规:\n")
		for _, k := range added {
			f := actual[k]
			fmt.Fprintf(os.Stderr, "      + %s\n        %s:%d %s\n", k, f.Path, f.Line, f.Msg)
		}
		fmt.Fprintf(os.Stderr, "    改法:%s\n", c.Hint)
		if c.Record {
			fmt.Fprintf(os.Stderr, "    ⚠️ %s 是**当前事实的记录**,不是债务清单 —— 这一行本来就该在里面。\n", path)
			fmt.Fprintf(os.Stderr, "       要判断的不是「能不能加」,而是「这次改动是不是有意的」。\n")
		} else {
			fmt.Fprintf(os.Stderr, "    ⛔ 别把它加进 %s 了事 —— 基线是历史债的清单,不是新债的收容所。\n", path)
		}
	}
	if len(removed) > 0 {
		if c.Record {
			fmt.Fprintf(os.Stderr, "  ✗ 基线里有对不上任何注册的条目(说明那条路由变了):\n")
		} else {
			fmt.Fprintf(os.Stderr, "  ✗ 基线里有已经不存在的条目(说明修好了):\n")
		}
		for _, k := range removed {
			fmt.Fprintf(os.Stderr, "      - %s\n", k)
		}
		if c.Record {
			fmt.Fprintf(os.Stderr, "    改法:⛔ 别只是删掉它 —— 它落空说明那条路由**变了**。\n")
			fmt.Fprintf(os.Stderr, "          路由还在、权限改了 → 把这行改成新的那一行(那次编辑就是重新批准);\n")
			fmt.Fprintf(os.Stderr, "          路由确实删了   → 才把这行删掉,和删路由放在同一个 PR 里。\n")
		} else {
			fmt.Fprintf(os.Stderr, "    改法:把上面这几行从 %s 删掉。棘轮只许往下走。\n", path)
		}
	}
	return false
}

func readBaseline(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out[line] = true
		}
	}
	return out, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
