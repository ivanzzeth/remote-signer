package main

import (
	"fmt"
	"go/ast"
	"sort"
	"strconv"
	"strings"
)

// ---------- mirror-structs: the same wire format, parsed by several structs ----------
//
// This check exists because the same mistake happened three times in one week,
// each time silently:
//
//   - A test case's `variables:` override was dropped, because
//     evm.JSTestCase had the field and the three structs mirroring it did not.
//     Cases meant to exercise "token_address unset" ran with USDC bound.
//   - A rule's `priority:` was dropped on the config path, because
//     config.RuleConfig had the field and cli/validate.RuleConfig did not.
//     Whitelist order decides which spending authorization applies.
//   - A template's `budget_metering:` was ignored by `remote-signer validate`,
//     because registry.templateYAML and config.templateFileContent had the field
//     and cli/validate.TemplateFile did not. An unresolvable budget unit passed
//     validation and took the daemon down at startup instead.
//
// None of them failed. A struct without the field simply does not see it, and
// encoding/json and gopkg.in/yaml both ignore input they have no home for. The
// only signal is behaviour that differs by which code path read the file.
//
// # What counts as a mirror
//
// Two structs that share at least minSharedTags serialization tags are treated
// as parsing the same thing. Tags, not Go field names: the tag is what decides
// what gets read out of the document, and two mirrors routinely disagree about
// Go naming while agreeing about the wire.
//
// A mirror pair is a finding when one side has a tag the other lacks. Equal
// sets are fine, and so is a struct that is a strict subset — no, it is not:
// a subset is exactly how all three of the above looked. Any difference counts.
//
// ⚠️ Deliberately not flagged: structs in different *modules* of meaning that
// happen to share generic names. minSharedTags is what keeps that in check, and
// the baseline carries the pairs that are intentional with the reason.

// Two conditions decide whether a pair is a mirror, and both exist because the
// naive version of this check produced 1333 pairs — every DTO in the tree that
// happens to carry `name` and `id`.
//
//   - minSharedTags: how many tags must overlap at all.
//   - minOverlapRatio: shared / len(smaller struct). A mirror is a struct that
//     reads *the same document*, so the smaller one is nearly a subset of the
//     larger. Two unrelated types sharing `id,name,enabled` are not.
//
// ⚠️ The ratio is against the smaller side on purpose. Every case this check was
// built for looked like a reduced copy: cli/validate.TemplateFile had 4 of the
// 12 fields registry.templateYAML reads, and the missing budget_metering is
// exactly what got ignored.
const (
	minSharedTags        = 3
	minSharedGenericOnly = 4
	minOverlapRatio      = 0.8
)

type taggedStruct struct {
	Pkg  string
	Name string
	Path string
	Line int
	Tags map[string]bool
}

func checkMirrorStructs(r *repo) ([]finding, error) {
	var structs []taggedStruct

	for _, f := range r.Files {
		ast.Inspect(f.File, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			// yamlTagged: this struct parses a configuration *file*.
			//
			// ⛔ Without this, response DTOs dominate: they are json-only, they
			// share `id`/`name`/`enabled` with everything, and two of them
			// diverging is an API design decision, not silent drift. The three
			// incidents this check exists for were all yaml on both sides.
			tags := map[string]bool{}
			yamlTagged := false
			for _, fld := range st.Fields.List {
				if fld.Tag == nil {
					continue
				}
				if structTagLookup(unquoteTag(fld.Tag.Value), "yaml") != "" {
					yamlTagged = true
				}
				if name := serializationTag(fld.Tag.Value); name != "" {
					tags[name] = true
				}
			}
			if yamlTagged && len(tags) >= minSharedTags {
				structs = append(structs, taggedStruct{
					Pkg:  f.Pkg,
					Name: ts.Name.Name,
					Path: f.Path,
					Line: f.Fset.Position(ts.Pos()).Line,
					Tags: tags,
				})
			}
			return true
		})
	}

	var out []finding
	for i := 0; i < len(structs); i++ {
		for j := i + 1; j < len(structs); j++ {
			a, b := structs[i], structs[j]
			if a.Pkg == b.Pkg {
				continue // same package: one format, one owner, not a mirror
			}
			shared := 0
			for t := range a.Tags {
				if b.Tags[t] {
					shared++
				}
			}
			smaller := len(a.Tags)
			if len(b.Tags) < smaller {
				smaller = len(b.Tags)
			}
			if shared < minSharedTags || float64(shared)/float64(smaller) < minOverlapRatio {
				continue
			}
			// Three tags that are all generic single words — name, type, enabled —
			// is a coincidence between unrelated config structs; four is a format.
			// A shared domain-specific key (budget_metering, signer_address) is
			// evidence on its own, so one of those lifts the floor back to three.
			//
			// ⚠️ The underscore is a proxy, not a rule about naming. It is here
			// because every key that turned out to matter in the three real
			// incidents had one, and every false pair this rejected did not.
			if shared < minSharedGenericOnly && !sharesDomainTag(a.Tags, b.Tags) {
				continue
			}
			onlyA := diffTags(a.Tags, b.Tags)
			onlyB := diffTags(b.Tags, a.Tags)
			if len(onlyA) == 0 && len(onlyB) == 0 {
				continue // identical field sets: mirrors, but in step
			}
			left, right := a, b
			missL, missR := onlyA, onlyB
			if key(a) > key(b) {
				left, right, missL, missR = b, a, onlyB, onlyA
			}
			msg := fmt.Sprintf("%s and %s share %d tags but disagree:", key(left), key(right), shared)
			if len(missL) > 0 {
				msg += fmt.Sprintf(" only %s has %s;", key(left), strings.Join(missL, ","))
			}
			if len(missR) > 0 {
				msg += fmt.Sprintf(" only %s has %s;", key(right), strings.Join(missR, ","))
			}
			out = append(out, finding{
				Check: "mirror-structs",
				Key:   key(left) + " <-> " + key(right),
				Path:  left.Path,
				Line:  left.Line,
				Msg:   strings.TrimSuffix(msg, ";"),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// sharesDomainTag reports whether the two structs agree on at least one
// domain-specific key, i.e. a compound one.
func sharesDomainTag(a, b map[string]bool) bool {
	for t := range a {
		if b[t] && strings.Contains(t, "_") {
			return true
		}
	}
	return false
}

func key(s taggedStruct) string { return s.Pkg + "." + s.Name }

func diffTags(a, b map[string]bool) []string {
	var out []string
	for t := range a {
		if !b[t] {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// serializationTag returns the yaml (preferred) or json name a field is read
// under, or "" when the field is not serialized.
//
// yaml wins because these are configuration files; a struct tagged only for
// json still counts, since the two formats describe the same document here.
func serializationTag(raw string) string {
	unq := unquoteTag(raw)
	for _, k := range []string{"yaml", "json"} {
		v := structTagLookup(unq, k)
		if v == "" {
			continue
		}
		name := strings.Split(v, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		return name
	}
	return ""
}

// structTagLookup is reflect.StructTag.Get without importing reflect for one call.
func structTagLookup(tag, key string) string {
	for tag != "" {
		i := 0
		for i < len(tag) && tag[i] == ' ' {
			i++
		}
		tag = tag[i:]
		if tag == "" {
			break
		}
		i = 0
		for i < len(tag) && tag[i] > ' ' && tag[i] != ':' && tag[i] != '"' {
			i++
		}
		if i == 0 || i+1 >= len(tag) || tag[i] != ':' || tag[i+1] != '"' {
			break
		}
		name := tag[:i]
		tag = tag[i+1:]
		i = 1
		for i < len(tag) && tag[i] != '"' {
			if tag[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(tag) {
			break
		}
		qvalue := tag[:i+1]
		tag = tag[i+1:]
		if name == key {
			value, err := strconv.Unquote(qvalue)
			if err != nil {
				return ""
			}
			return value
		}
	}
	return ""
}

func unquoteTag(raw string) string {
	if unq, err := strconv.Unquote(raw); err == nil {
		return unq
	}
	return raw
}
