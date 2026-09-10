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
		fmt.Fprintf(os.Stderr, "    ⛔ 别把它加进 %s 了事 —— 基线是历史债的清单,不是新债的收容所。\n", path)
	}
	if len(removed) > 0 {
		fmt.Fprintf(os.Stderr, "  ✗ 基线里有已经不存在的条目(说明修好了):\n")
		for _, k := range removed {
			fmt.Fprintf(os.Stderr, "      - %s\n", k)
		}
		fmt.Fprintf(os.Stderr, "    改法:把上面这几行从 %s 删掉。棘轮只许往下走。\n", path)
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
