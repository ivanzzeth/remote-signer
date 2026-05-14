// migrate-rules rewrites legacy template/preset YAML in rules/templates and
// rules/presets into the v0.3 shape that internal/core/registry expects.
//
// Transformations:
//
// Templates (rules/templates/*.template[.js].yaml):
//   - Move to rules/templates/evm/<stem>.yaml (drop .template[.js] infix)
//   - Add a top-level `name:` if missing (derived from rules[0].name or
//     from the filename stem)
//   - Rename variable types: uint256 → bigint, uint256_list → bigint_list
//
// Presets (rules/presets/*.preset[.js].yaml):
//   - Move to rules/presets/evm/<stem>.yaml (drop .preset[.js] infix)
//   - Drop template_paths and template_names (replaced by template_ids)
//   - Add template_ids: derived from template_paths basenames →
//     "evm/<stem>"
//   - Convert override_hints: [string] → operator_overrides:
//     [{name, required: false}]
//
// The tool preserves comments where yaml.Node round-trip allows. Run with
// -dry-run to see what would change; without the flag it rewrites in place
// and deletes the legacy file once the new one is written.
//
// Files that don't match the legacy filename pattern (e.g. our new
// sign_type_allowlist.yaml) are skipped — they're assumed already in the
// new shape.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	dryRun   = flag.Bool("dry-run", false, "Print planned changes; do not write")
	rulesDir = flag.String("rules-dir", "rules", "Path to rules directory")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "migrate-rules:", err)
		os.Exit(1)
	}
}

func run() error {
	templatesDir := filepath.Join(*rulesDir, "templates")
	presetsDir := filepath.Join(*rulesDir, "presets")

	// Compute the templates' collision map first so presets can reuse
	// it when rewriting template_paths → template_ids: a preset that
	// referenced predict_trading.template.js.yaml maps to template ID
	// "evm/predict_trading_js", not "evm/predict_trading".
	tmplEntries, err := os.ReadDir(templatesDir)
	if err != nil {
		return fmt.Errorf("read templates dir: %w", err)
	}
	tmplCollisions := stemsByVariant(tmplEntries, isLegacyTemplate, plainTemplateStem)

	if err := migrateTemplates(templatesDir); err != nil {
		return fmt.Errorf("templates: %w", err)
	}
	if err := migratePresets(presetsDir, tmplCollisions); err != nil {
		return fmt.Errorf("presets: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

func migrateTemplates(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	stems := stemsByVariant(entries, isLegacyTemplate, plainTemplateStem)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isLegacyTemplate(name) {
			continue
		}
		if err := migrateTemplateFile(dir, name, stems); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// stemsByVariant tallies how many legacy variants share each plain stem,
// so the migration knows when to disambiguate the `.js` file by adding
// a `_js` suffix. Without this every collision (predict_trading,
// predict_enable_trading, predict_eoa_bnb) would silently clobber the
// solidity variant.
func stemsByVariant(entries []os.DirEntry, isLegacy func(string) bool, plain func(string) string) map[string]int {
	counts := make(map[string]int)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !isLegacy(e.Name()) {
			continue
		}
		counts[plain(e.Name())]++
	}
	return counts
}

// isLegacyTemplate matches the two legacy filename patterns: foo.template.yaml
// and foo.template.js.yaml. Anything else (foo.yaml, foo.yml) is assumed to
// already be in the new shape and is left alone.
func isLegacyTemplate(name string) bool {
	return strings.HasSuffix(name, ".template.yaml") || strings.HasSuffix(name, ".template.js.yaml")
}

// plainTemplateStem returns the stem with .template[.js] stripped and
// no _js disambiguation suffix. Used to detect collisions across the
// JS / Solidity variants of the same logical template.
func plainTemplateStem(name string) string {
	stem := strings.TrimSuffix(name, ".yaml")
	stem = strings.TrimSuffix(stem, ".js")
	stem = strings.TrimSuffix(stem, ".template")
	return stem
}

// stripTemplateInfix returns the new ID stem for a legacy file. When
// both the .js and non-.js variants exist for the same plain stem, the
// .js file gets a `_js` suffix so it doesn't overwrite its solidity
// counterpart. The non-.js file keeps the plain stem.
func stripTemplateInfix(name string, collisions map[string]int) string {
	plain := plainTemplateStem(name)
	if collisions[plain] > 1 && strings.HasSuffix(name, ".js.yaml") {
		return plain + "_js"
	}
	return plain
}

func migrateTemplateFile(dir, name string, collisions map[string]int) error {
	src := filepath.Join(dir, name)
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	root, doc, err := parseDocument(raw)
	if err != nil {
		return err
	}

	stem := stripTemplateInfix(name, collisions)

	// Ensure top-level `name:`. Use rules[0].name if available, else
	// derive from stem.
	if !mapHas(doc, "name") {
		derived := deriveTemplateName(doc, stem)
		prependScalar(doc, "name", derived)
	}

	// Rename variable types in-place.
	renameVariableTypes(doc)

	out, err := marshalDocument(root)
	if err != nil {
		return err
	}

	target := filepath.Join(dir, "evm", stem+".yaml")
	return commit(src, target, out)
}

// deriveTemplateName picks the best candidate for the new top-level
// `name:` field. The first rule's name is the most informative when
// available; falling back to a humanised filename keeps things readable
// for templates that don't have rule-level names.
func deriveTemplateName(doc *yaml.Node, stem string) string {
	if rules := mapGet(doc, "rules"); rules != nil && rules.Kind == yaml.SequenceNode && len(rules.Content) > 0 {
		first := rules.Content[0]
		if n := mapGet(first, "name"); n != nil && n.Value != "" {
			return n.Value
		}
	}
	return humaniseStem(stem)
}

func humaniseStem(stem string) string {
	parts := strings.Split(stem, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		// Keep acronyms upper-case-ish: erc20 → ERC20, eip4337 → EIP4337
		if isLikelyAcronym(p) {
			parts[i] = strings.ToUpper(p)
		} else {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

func isLikelyAcronym(s string) bool {
	// crude heuristic: starts with 3+ letters then digits ("erc20",
	// "eip4337") or is all-letters and ≤4 chars
	letters, digits := 0, 0
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			if digits > 0 {
				return false
			}
			letters++
		case r >= '0' && r <= '9':
			digits++
		default:
			_ = i
			return false
		}
	}
	if letters >= 3 && digits >= 1 {
		return true
	}
	if digits == 0 && letters <= 4 {
		return true
	}
	return false
}

// renameVariableTypes walks the doc's `variables:` sequence and updates
// any uint256 / uint256_list type tags to bigint / bigint_list. Other
// fields are left untouched so YAML comments around them survive.
func renameVariableTypes(doc *yaml.Node) {
	vars := mapGet(doc, "variables")
	if vars == nil || vars.Kind != yaml.SequenceNode {
		return
	}
	for _, v := range vars.Content {
		if v.Kind != yaml.MappingNode {
			continue
		}
		t := mapGet(v, "type")
		if t == nil {
			continue
		}
		switch t.Value {
		case "uint256":
			t.Value = "bigint"
		case "uint256_list":
			t.Value = "bigint_list"
		}
	}
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

func migratePresets(dir string, templateCollisions map[string]int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	stems := stemsByVariant(entries, isLegacyPreset, plainPresetStem)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isLegacyPreset(name) {
			continue
		}
		if err := migratePresetFile(dir, name, stems, templateCollisions); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func isLegacyPreset(name string) bool {
	return strings.HasSuffix(name, ".preset.yaml") || strings.HasSuffix(name, ".preset.js.yaml")
}

func plainPresetStem(name string) string {
	stem := strings.TrimSuffix(name, ".yaml")
	stem = strings.TrimSuffix(stem, ".js")
	stem = strings.TrimSuffix(stem, ".preset")
	return stem
}

func stripPresetInfix(name string, collisions map[string]int) string {
	plain := plainPresetStem(name)
	if collisions[plain] > 1 && strings.HasSuffix(name, ".js.yaml") {
		return plain + "_js"
	}
	return plain
}

func migratePresetFile(dir, name string, presetCollisions, templateCollisions map[string]int) error {
	src := filepath.Join(dir, name)
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	root, doc, err := parseDocument(raw)
	if err != nil {
		return err
	}

	stem := stripPresetInfix(name, presetCollisions)

	// Derive template_ids from template_paths.
	templateIDs := derivedTemplateIDs(doc, templateCollisions)
	if len(templateIDs) > 0 {
		setStringSliceField(doc, "template_ids", templateIDs)
	}

	// Drop the legacy ID-ish fields once template_ids is in place.
	mapDelete(doc, "template_paths")
	mapDelete(doc, "template_names")

	// Convert override_hints → operator_overrides.
	convertOverrideHints(doc)

	// Variable types in preset variables block — presets don't declare
	// types (templates do), but if a preset somehow references uint256
	// values they're free-form strings; nothing to rename here.

	out, err := marshalDocument(root)
	if err != nil {
		return err
	}

	target := filepath.Join(dir, "evm", stem+".yaml")
	return commit(src, target, out)
}

// derivedTemplateIDs maps each `template_paths` entry (which points at a
// legacy template file) to its new ID — the basename without the
// .template[.js].yaml infix, prefixed with "evm/" since every existing
// template lives there post-migration. The templateCollisions map lets
// us add the `_js` suffix where the JS variant collides with a Solidity
// counterpart, matching what migrateTemplates does to the actual files.
// If no template_paths is present, returns nil and lets the caller leave
// template_ids untouched (an operator may have already hand-edited the
// preset).
func derivedTemplateIDs(doc *yaml.Node, templateCollisions map[string]int) []string {
	paths := mapGet(doc, "template_paths")
	if paths == nil || paths.Kind != yaml.SequenceNode {
		return nil
	}
	var ids []string
	for _, p := range paths.Content {
		if p.Kind != yaml.ScalarNode {
			continue
		}
		base := filepath.Base(p.Value)
		stem := stripTemplateInfix(base, templateCollisions)
		ids = append(ids, "evm/"+stem)
	}
	return ids
}

// convertOverrideHints rewrites the legacy
//
//	override_hints:
//	  - foo
//	  - bar
//
// to the new
//
//	operator_overrides:
//	  - name: foo
//	    required: false
//	  - name: bar
//	    required: false
//
// shape. Required defaults to false; operators who want the new
// required:true semantics can hand-edit the migrated file.
func convertOverrideHints(doc *yaml.Node) {
	hints := mapGet(doc, "override_hints")
	if hints == nil || hints.Kind != yaml.SequenceNode {
		return
	}
	overrides := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, h := range hints.Content {
		if h.Kind != yaml.ScalarNode || h.Value == "" {
			continue
		}
		item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		item.Content = append(item.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "name"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: h.Value},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "required"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"},
		)
		overrides.Content = append(overrides.Content, item)
	}
	mapDelete(doc, "override_hints")
	mapAppend(doc, "operator_overrides", overrides)
}

// ---------------------------------------------------------------------------
// yaml.Node helpers
// ---------------------------------------------------------------------------

func parseDocument(raw []byte) (*yaml.Node, *yaml.Node, error) {
	root := &yaml.Node{}
	if err := yaml.Unmarshal(raw, root); err != nil {
		return nil, nil, fmt.Errorf("yaml parse: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil, fmt.Errorf("expected a YAML document")
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("expected a mapping at document root")
	}
	return root, doc, nil
}

func marshalDocument(root *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mapHas(m *yaml.Node, key string) bool {
	return mapGet(m, key) != nil
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(m.Content)-1; i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapDelete(m *yaml.Node, key string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(m.Content)-1; i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func mapAppend(m *yaml.Node, key string, value *yaml.Node) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		value,
	)
}

func prependScalar(m *yaml.Node, key, value string) {
	pair := []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	}
	m.Content = append(pair, m.Content...)
}

func setStringSliceField(m *yaml.Node, key string, values []string) {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range values {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
	}
	if existing := mapGet(m, key); existing != nil {
		*existing = *seq
		return
	}
	mapAppend(m, key, seq)
}

// ---------------------------------------------------------------------------
// Write / move
// ---------------------------------------------------------------------------

func commit(src, target string, contents []byte) error {
	if *dryRun {
		fmt.Printf("[dry] %s → %s\n", src, target)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(target, contents, 0o644); err != nil {
		return err
	}
	if src != target {
		if err := os.Remove(src); err != nil {
			return err
		}
	}
	fmt.Printf("migrated %s → %s\n", src, target)
	return nil
}
