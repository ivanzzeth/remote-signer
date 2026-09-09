package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// goFile is one parsed non-test source file that ships in the binary.
type goFile struct {
	Path    string // repo-relative, slash-separated
	Pkg     string // repo-relative directory, e.g. "internal/core/service"
	File    *ast.File
	Fset    *token.FileSet
	Imports []importRef
}

type importRef struct {
	Path string // full import path
	Line int
}

type repo struct {
	Module string
	Files  []*goFile
}

// loadRepo parses every Go file that can reach the production binary.
//
// ⚠️ "Production" is decided by build tag and filename suffix, the same two
// criteria the compiler uses — not by whether the path looks test-ish. A file
// called shared_test_helpers.go with no build tag ships, and seven of them did.
func loadRepo(root string) (*repo, error) {
	mod, err := moduleName(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	r := &repo{Module: mod}
	fset := token.NewFileSet()

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			switch name {
			case "vendor", "node_modules", ".git", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			// A file that does not parse is not this tool's problem to report:
			// the compiler already says so, louder and with better messages.
			return nil
		}
		if hasBuildConstraint(f) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		gf := &goFile{Path: rel, Pkg: filepath.ToSlash(filepath.Dir(rel)), File: f, Fset: fset}
		for _, im := range f.Imports {
			p, uerr := strconv.Unquote(im.Path.Value)
			if uerr != nil {
				continue
			}
			gf.Imports = append(gf.Imports, importRef{Path: p, Line: fset.Position(im.Pos()).Line})
		}
		r.Files = append(r.Files, gf)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// hasBuildConstraint reports whether the file carries a //go:build line.
// Such files (e2e, integration, tooling) are not in the daemon.
func hasBuildConstraint(f *ast.File) bool {
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:build ") {
				return true
			}
		}
		// Build constraints precede the package clause; once past it, stop.
		if cg.Pos() > f.Package {
			break
		}
	}
	return false
}

func moduleName(gomod string) (string, error) {
	b, err := os.ReadFile(gomod)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}
	return "", fmt.Errorf("no module line in %s", gomod)
}

// layerOf returns the layer a repo-relative package directory belongs to,
// by longest matching prefix. Returns nil when nothing matches.
func layerOf(pkg string) *layer {
	var best *layer
	bestLen := -1
	for i := range layers {
		for _, p := range layers[i].Prefixes {
			if pkg == p || strings.HasPrefix(pkg, p+"/") {
				if len(p) > bestLen {
					bestLen = len(p)
					best = &layers[i]
				}
			}
		}
	}
	return best
}

func listUnclassified(r *repo) {
	seen := map[string]bool{}
	var out []string
	for _, f := range r.Files {
		if seen[f.Pkg] {
			continue
		}
		seen[f.Pkg] = true
		if !strings.HasPrefix(f.Pkg, "internal/") {
			continue
		}
		if layerOf(f.Pkg) == nil {
			out = append(out, f.Pkg)
		}
	}
	if len(out) == 0 {
		fmt.Println("every internal package is assigned to a layer")
		return
	}
	fmt.Println("packages matching no layer (assign them in layers.go):")
	for _, p := range out {
		fmt.Println("  " + p)
	}
}

// sourceOf re-reads a file's bytes. Used only for "does this file mention X at
// all" questions where a declaration-level answer is not required.
func sourceOf(f *goFile) string {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return ""
	}
	return string(b)
}
