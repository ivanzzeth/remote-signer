package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// parseSources builds a repo from literal sources, keyed pkg -> file body.
func parseSources(t *testing.T, srcByPkg map[string]string) *repo {
	t.Helper()
	r := &repo{Module: "example.com/m"}
	for pkg, body := range srcByPkg {
		fset := token.NewFileSet()
		name := pkg + "/x.go"
		f, err := parser.ParseFile(fset, name, body, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", pkg, err)
		}
		r.Files = append(r.Files, &goFile{Path: name, Pkg: pkg, File: f, Fset: fset})
	}
	return r
}

func mirrorKeys(t *testing.T, srcByPkg map[string]string) []string {
	t.Helper()
	found, err := checkMirrorStructs(parseSources(t, srcByPkg))
	if err != nil {
		t.Fatalf("checkMirrorStructs: %v", err)
	}
	var keys []string
	for _, f := range found {
		keys = append(keys, f.Key)
	}
	return keys
}

// TestMirrorStructs_CatchesADroppedField is the regression this check exists for.
//
// The shape is taken from the real incident: internal/config.RuleConfig grew a
// priority field, internal/cli/validate.RuleConfig did not, and `remote-signer
// validate` silently dropped the rule ordering it was asked to check. Nothing
// failed — yaml has no home for the key, so it is discarded.
func TestMirrorStructs_CatchesADroppedField(t *testing.T) {
	keys := mirrorKeys(t, map[string]string{
		"internal/config": `package config
type RuleConfig struct {
	Name     string ` + "`yaml:\"name\"`" + `
	Type     string ` + "`yaml:\"type\"`" + `
	Mode     string ` + "`yaml:\"mode\"`" + `
	ChainID  string ` + "`yaml:\"chain_id,omitempty\"`" + `
	Config   map[string]any ` + "`yaml:\"config\"`" + `
	Priority *int   ` + "`yaml:\"priority,omitempty\"`" + `
}`,
		"internal/cli/validate": `package validate
type RuleConfig struct {
	Name string ` + "`yaml:\"name\"`" + `
	Type string ` + "`yaml:\"type\"`" + `
	Mode string ` + "`yaml:\"mode\"`" + `
	ChainID string ` + "`yaml:\"chain_id,omitempty\"`" + `
	Config  map[string]any ` + "`yaml:\"config\"`" + `
}`,
	})
	if len(keys) != 1 {
		t.Fatalf("want exactly one mirror finding, got %d: %v", len(keys), keys)
	}
	if !strings.Contains(keys[0], "config.RuleConfig") || !strings.Contains(keys[0], "validate.RuleConfig") {
		t.Errorf("finding does not name both sides: %s", keys[0])
	}

	found, _ := checkMirrorStructs(parseSources(t, map[string]string{
		"internal/config": `package config
type RuleConfig struct {
	Name     string ` + "`yaml:\"name\"`" + `
	Type     string ` + "`yaml:\"type\"`" + `
	Mode     string ` + "`yaml:\"mode\"`" + `
	ChainID  string ` + "`yaml:\"chain_id,omitempty\"`" + `
	Config   map[string]any ` + "`yaml:\"config\"`" + `
	Priority *int   ` + "`yaml:\"priority,omitempty\"`" + `
}`,
		"internal/cli/validate": `package validate
type RuleConfig struct {
	Name string ` + "`yaml:\"name\"`" + `
	Type string ` + "`yaml:\"type\"`" + `
	Mode string ` + "`yaml:\"mode\"`" + `
	ChainID string ` + "`yaml:\"chain_id,omitempty\"`" + `
	Config  map[string]any ` + "`yaml:\"config\"`" + `
}`,
	}))
	// The message must say which field, or the finding cannot be acted on
	// without re-deriving the diff by hand.
	if !strings.Contains(found[0].Msg, "priority") {
		t.Errorf("message does not name the missing field: %s", found[0].Msg)
	}
}

// TestMirrorStructs_InStepIsClean: mirrors are allowed to exist. Only drift is
// a finding — otherwise the check would demand a refactor for every DTO pair
// and get switched off.
func TestMirrorStructs_InStepIsClean(t *testing.T) {
	keys := mirrorKeys(t, map[string]string{
		"a": `package a
type T struct {
	Name string ` + "`yaml:\"name\"`" + `
	Type string ` + "`yaml:\"type\"`" + `
	Mode string ` + "`yaml:\"mode\"`" + `
}`,
		"b": `package b
type U struct {
	N string ` + "`yaml:\"name\"`" + `
	T string ` + "`yaml:\"type\"`" + `
	M string ` + "`yaml:\"mode\"`" + `
}`,
	})
	if len(keys) != 0 {
		t.Errorf("identical tag sets must not be a finding, got %v", keys)
	}
}

// TestMirrorStructs_IgnoresJSONOnlyDTOs guards the tightening that took this
// check from 1333 findings to 8. Response DTOs share id/name/enabled with
// everything in the tree; two of them differing is an API decision, not drift.
func TestMirrorStructs_IgnoresJSONOnlyDTOs(t *testing.T) {
	keys := mirrorKeys(t, map[string]string{
		"a": `package a
type Resp struct {
	ID      string ` + "`json:\"id\"`" + `
	Name    string ` + "`json:\"name\"`" + `
	Enabled bool   ` + "`json:\"enabled\"`" + `
}`,
		"b": `package b
type Other struct {
	ID      string ` + "`json:\"id\"`" + `
	Name    string ` + "`json:\"name\"`" + `
	Enabled bool   ` + "`json:\"enabled\"`" + `
	Extra   string ` + "`json:\"extra\"`" + `
}`,
	})
	if len(keys) != 0 {
		t.Errorf("json-only DTOs must not be mirrors, got %v", keys)
	}
}

// TestMirrorStructs_IgnoresIncidentalOverlap: two config structs that merely
// share a few generic keys are not mirrors of one format. Three single-word
// tags is what every unrelated pair in this tree has in common; without this
// floor the check reported 1333 pairs and would have been switched off.
func TestMirrorStructs_IgnoresIncidentalOverlap(t *testing.T) {
	keys := mirrorKeys(t, map[string]string{
		"a": `package a
type Server struct {
	Name    string ` + "`yaml:\"name\"`" + `
	Type    string ` + "`yaml:\"type\"`" + `
	Enabled bool   ` + "`yaml:\"enabled\"`" + `
}`,
		"b": `package b
type Chain struct {
	Name     string ` + "`yaml:\"name\"`" + `
	Type     string ` + "`yaml:\"type\"`" + `
	Enabled  bool   ` + "`yaml:\"enabled\"`" + `
	RPC      string ` + "`yaml:\"rpc\"`" + `
	ChainID  string ` + "`yaml:\"chain_id\"`" + `
	Explorer string ` + "`yaml:\"explorer\"`" + `
	Symbol   string ` + "`yaml:\"symbol\"`" + `
}`,
	})
	if len(keys) != 0 {
		t.Errorf("3 of 7 shared tags is incidental, not a mirror: %v", keys)
	}
}

// TestMirrorStructs_SamePackageIsNotAMirror: one package owning two views of a
// format is a deliberate local choice with a single owner, and the drift this
// check hunts happens across package boundaries.
func TestMirrorStructs_SamePackageIsNotAMirror(t *testing.T) {
	keys := mirrorKeys(t, map[string]string{
		"a": `package a
type T struct {
	Name string ` + "`yaml:\"name\"`" + `
	Type string ` + "`yaml:\"type\"`" + `
	Mode string ` + "`yaml:\"mode\"`" + `
}
type U struct {
	Name string ` + "`yaml:\"name\"`" + `
	Type string ` + "`yaml:\"type\"`" + `
}`,
	})
	if len(keys) != 0 {
		t.Errorf("same-package structs must not be mirrors, got %v", keys)
	}
}

func TestSerializationTag(t *testing.T) {
	for _, tc := range []struct{ tag, want string }{
		{"`yaml:\"name\"`", "name"},
		{"`yaml:\"budget_metering,omitempty\"`", "budget_metering"},
		{"`json:\"priority,omitempty\"`", "priority"},
		{"`yaml:\"-\" json:\"id\"`", "id"}, // yaml skipped, json still reads it
		{"`yaml:\"a\" json:\"b\"`", "a"},   // yaml wins: these are config files
		{"`json:\"-\"`", ""},               // not serialized at all
		{"`gorm:\"primaryKey\"`", ""},      // storage tags are not a wire format
	} {
		if got := serializationTag(tc.tag); got != tc.want {
			t.Errorf("serializationTag(%s) = %q, want %q", tc.tag, got, tc.want)
		}
	}
}
