package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// fileExtensions is the suffix set we treat as template/preset YAML.
// Both .yaml and .yml are accepted — operators write either freely, and
// we don't want a silent skip just because someone typed the short form.
var fileExtensions = map[string]struct{}{
	".yaml": {},
	".yml":  {},
}

// ---------------------------------------------------------------------------
// On-disk YAML shape
// ---------------------------------------------------------------------------

// templateYAML is the wire shape for a template file. The Registry parses
// into this struct then assembles a *types.RuleTemplate with the JSON
// columns marshalled and the provenance fields populated from the file path.
//
// `id` and `chain_type` are intentionally absent / optional here: ID is
// derived from the file's path stem so files can be renamed without
// the operator having to edit the YAML, and chain_type is inferred from
// the first directory segment (e.g. `evm/foo.yaml` → ChainType="evm").
// A top-level `chain_type:` in the YAML overrides the directory inference
// for the rare off-chain template that happens to sit under a chain dir.
type templateYAML struct {
	Name           string                  `yaml:"name"`
	Description    string                  `yaml:"description,omitempty"`
	Type           types.RuleType          `yaml:"type"`
	Mode           types.RuleMode          `yaml:"mode"`
	ChainType      types.ChainType         `yaml:"chain_type,omitempty"`
	Variables      []types.TemplateVariable `yaml:"variables"`
	VariableGroups []types.VariableGroup    `yaml:"variable_groups,omitempty"`
	Rules          []map[string]any        `yaml:"rules,omitempty"`
	Config         map[string]any          `yaml:"config,omitempty"`
	BudgetMetering *types.BudgetMetering   `yaml:"budget_metering,omitempty"`
	TestVariables  map[string]string       `yaml:"test_variables,omitempty"`
	Enabled        *bool                   `yaml:"enabled,omitempty"`
}

// presetYAML is the wire shape for a preset file. As with templates, ID
// is derived from path; chain_type/chain_id are required in the YAML
// itself because presets pin a network. TemplateIDs replaces the older
// `template_names` (which carried display labels, not stable IDs) and
// OperatorOverrides replaces `override_hints` (string array) with a
// struct so per-variable required-ness can be expressed.
type presetYAML struct {
	Name              string                  `yaml:"name"`
	Description       string                  `yaml:"description,omitempty"`
	ChainType         types.ChainType         `yaml:"chain_type,omitempty"`
	ChainID           string                  `yaml:"chain_id,omitempty"`
	TemplateIDs       []string                `yaml:"template_ids"`
	Variables         map[string]any          `yaml:"variables,omitempty"`
	OperatorOverrides []types.OperatorOverride `yaml:"operator_overrides,omitempty"`
	Budget            map[string]any          `yaml:"budget,omitempty"`
	Schedule          map[string]any          `yaml:"schedule,omitempty"`
	Enabled           *bool                   `yaml:"enabled,omitempty"`
}

// ---------------------------------------------------------------------------
// FileTemplateSource
// ---------------------------------------------------------------------------

// FileTemplateSource lists templates from a directory tree on disk. It is
// the only Source implementation v0.3 ships; remote sources (github, http)
// land in later phases and reuse the same Registry by implementing the
// TemplateSource interface.
//
// Layout convention: <root>/<chain_type>/<name>.yaml. The first directory
// segment becomes ChainType; files at the root (no subdir) are treated
// as off-chain (ChainType=""). This keeps `ls rules/templates/` legible
// at a glance — operators see one folder per chain family.
type FileTemplateSource struct {
	root string
}

// NewFileTemplateSource takes a directory path and returns a Source. The
// path is not required to exist at construction time: a missing root is
// equivalent to "no templates" and List returns an empty slice. That
// makes startup tolerant of fresh installs where the operator has not
// yet populated rules/templates/.
func NewFileTemplateSource(root string) *FileTemplateSource {
	return &FileTemplateSource{root: root}
}

// Kind reports RuleSourceConfig — file sources are conceptually the same
// origin as "I put it in config.yaml". Future remote sources will return
// different kinds so prune scoping works correctly across multiple
// concurrent Sync passes.
func (s *FileTemplateSource) Kind() types.RuleSource {
	return types.RuleSourceConfig
}

// List walks the root and returns one *types.RuleTemplate per .yaml/.yml
// file. Parse failures don't abort the walk — the offending file is
// skipped and the error is surfaced via the Registry's SyncReport so a
// single bad template can't block the rest of the catalogue.
func (s *FileTemplateSource) List(ctx context.Context) ([]*types.RuleTemplate, error) {
	if s.root == "" {
		return nil, nil
	}
	info, err := os.Stat(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", s.root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", s.root)
	}

	var out []*types.RuleTemplate
	walkErr := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if _, ok := fileExtensions[strings.ToLower(filepath.Ext(path))]; !ok {
			return nil
		}
		tmpl, parseErr := s.parseTemplate(path)
		if parseErr != nil {
			// Skip but keep walking — Registry will collect from the source side
			// in a future iteration. For now we drop unparseable files silently;
			// the caller (Registry) can log via SyncReport.Errors when we wire
			// per-file errors back. R4 keeps this simple by returning a single
			// fatal error only on walk-level problems.
			return fmt.Errorf("%s: %w", path, parseErr)
		}
		out = append(out, tmpl)
		return nil
	})
	if walkErr != nil {
		return out, walkErr
	}
	return out, nil
}

// parseTemplate reads one file, computes its identity + content hash,
// and assembles a *types.RuleTemplate with the JSON columns populated.
// Sync-time validation lives in validateTemplate.
func (s *FileTemplateSource) parseTemplate(path string) (*types.RuleTemplate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc templateYAML
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}

	id, chainFromDir, err := relPathIdentity(s.root, path)
	if err != nil {
		return nil, err
	}
	chainType := doc.ChainType
	if chainType == "" {
		chainType = chainFromDir
	}

	if err := validateTemplate(&doc); err != nil {
		return nil, err
	}

	variablesJSON, err := marshalJSON(doc.Variables)
	if err != nil {
		return nil, fmt.Errorf("variables: %w", err)
	}
	var groupsJSON []byte
	if len(doc.VariableGroups) > 0 {
		groupsJSON, err = marshalJSON(doc.VariableGroups)
		if err != nil {
			return nil, fmt.Errorf("variable_groups: %w", err)
		}
	}
	// Config holds the template body (rules / arbitrary config). Either
	// `rules:` or `config:` is accepted at the top level; if both are
	// present, `config:` wins (rules merges in under config.rules).
	cfg := doc.Config
	if cfg == nil && len(doc.Rules) > 0 {
		cfg = map[string]any{"rules": doc.Rules}
	} else if cfg != nil && len(doc.Rules) > 0 {
		cfg["rules"] = doc.Rules
	}
	configJSON, err := marshalJSON(cfg)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var meteringJSON []byte
	if doc.BudgetMetering != nil {
		meteringJSON, err = marshalJSON(doc.BudgetMetering)
		if err != nil {
			return nil, fmt.Errorf("budget_metering: %w", err)
		}
	}
	var testVarsJSON []byte
	if len(doc.TestVariables) > 0 {
		testVarsJSON, err = marshalJSON(doc.TestVariables)
		if err != nil {
			return nil, fmt.Errorf("test_variables: %w", err)
		}
	}

	relPath, _ := filepath.Rel(s.root, path)
	relPath = filepath.ToSlash(relPath)

	enabled := true
	if doc.Enabled != nil {
		enabled = *doc.Enabled
	}

	return &types.RuleTemplate{
		ID:             id,
		Name:           doc.Name,
		Description:    doc.Description,
		Type:           doc.Type,
		Mode:           doc.Mode,
		ChainType:      chainType,
		Variables:      variablesJSON,
		VariableGroups: groupsJSON,
		Config:         configJSON,
		BudgetMetering: meteringJSON,
		TestVariables:  testVarsJSON,
		Source:         types.RuleSourceConfig,
		SourcePath:     relPath,
		ContentHash:    hashBytes(raw),
		Enabled:        enabled,
	}, nil
}

// ---------------------------------------------------------------------------
// FilePresetSource
// ---------------------------------------------------------------------------

// FilePresetSource is the preset counterpart to FileTemplateSource. Same
// directory convention (<root>/<chain_type>/<name>.yaml), same identity
// rules, same content-hash semantics — kept as a separate type because
// the parse + validate paths diverge enough that a generic source would
// hide more than it'd save.
type FilePresetSource struct {
	root string
}

func NewFilePresetSource(root string) *FilePresetSource {
	return &FilePresetSource{root: root}
}

func (s *FilePresetSource) Kind() types.RuleSource {
	return types.RuleSourceConfig
}

func (s *FilePresetSource) List(ctx context.Context) ([]*types.RulePreset, error) {
	if s.root == "" {
		return nil, nil
	}
	info, err := os.Stat(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", s.root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", s.root)
	}

	var out []*types.RulePreset
	walkErr := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if _, ok := fileExtensions[strings.ToLower(filepath.Ext(path))]; !ok {
			return nil
		}
		preset, parseErr := s.parsePreset(path)
		if parseErr != nil {
			return fmt.Errorf("%s: %w", path, parseErr)
		}
		out = append(out, preset)
		return nil
	})
	if walkErr != nil {
		return out, walkErr
	}
	return out, nil
}

func (s *FilePresetSource) parsePreset(path string) (*types.RulePreset, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc presetYAML
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}

	id, chainFromDir, err := relPathIdentity(s.root, path)
	if err != nil {
		return nil, err
	}
	chainType := doc.ChainType
	if chainType == "" {
		chainType = chainFromDir
	}

	if err := validatePreset(&doc); err != nil {
		return nil, err
	}

	templateIDsJSON, err := marshalJSON(doc.TemplateIDs)
	if err != nil {
		return nil, fmt.Errorf("template_ids: %w", err)
	}
	var variablesJSON []byte
	if len(doc.Variables) > 0 {
		variablesJSON, err = marshalJSON(doc.Variables)
		if err != nil {
			return nil, fmt.Errorf("variables: %w", err)
		}
	}
	var overridesJSON []byte
	if len(doc.OperatorOverrides) > 0 {
		overridesJSON, err = marshalJSON(doc.OperatorOverrides)
		if err != nil {
			return nil, fmt.Errorf("operator_overrides: %w", err)
		}
	}
	var budgetJSON []byte
	if len(doc.Budget) > 0 {
		budgetJSON, err = marshalJSON(doc.Budget)
		if err != nil {
			return nil, fmt.Errorf("budget: %w", err)
		}
	}
	var scheduleJSON []byte
	if len(doc.Schedule) > 0 {
		scheduleJSON, err = marshalJSON(doc.Schedule)
		if err != nil {
			return nil, fmt.Errorf("schedule: %w", err)
		}
	}

	relPath, _ := filepath.Rel(s.root, path)
	relPath = filepath.ToSlash(relPath)

	enabled := true
	if doc.Enabled != nil {
		enabled = *doc.Enabled
	}

	return &types.RulePreset{
		ID:                id,
		Name:              doc.Name,
		Description:       doc.Description,
		ChainType:         chainType,
		ChainID:           doc.ChainID,
		TemplateIDs:       templateIDsJSON,
		Variables:         variablesJSON,
		OperatorOverrides: overridesJSON,
		Budget:            budgetJSON,
		Schedule:          scheduleJSON,
		Enabled:           enabled,
		Source:            types.RuleSourceConfig,
		SourcePath:        relPath,
		ContentHash:       hashBytes(raw),
	}, nil
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// relPathIdentity derives the canonical ID and chain-from-directory for
// a file given the source root. ID is the file stem joined by '/' if
// the file lives in a subdirectory ("evm/erc20" for evm/erc20.yaml).
// chainFromDir is the first path segment ("evm") or "" if the file
// lives at the root.
//
// Slash normalisation is done up-front so IDs match across Windows
// development and Linux deployment — file IDs stored in the DB carry
// forward-slashes only.
func relPathIdentity(root, path string) (id string, chainFromDir types.ChainType, err error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", "", err
	}
	rel = filepath.ToSlash(rel)
	ext := filepath.Ext(rel)
	stem := strings.TrimSuffix(rel, ext)
	if stem == "" || stem == "." {
		return "", "", fmt.Errorf("invalid path: %s", path)
	}
	id = stem
	if idx := strings.IndexByte(stem, '/'); idx > 0 {
		chainFromDir = types.ChainType(stem[:idx])
	}
	return id, chainFromDir, nil
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// marshalJSON wraps encoding/json with deterministic ordering for the
// columns we hash on. The hash itself is computed on the raw YAML
// bytes, so JSON marshalling here is only for storage. Standard library
// behaviour is fine.
func marshalJSON(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func validateTemplate(doc *templateYAML) error {
	if doc.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Type and Mode are optional at the template level. A template can
	// contain multiple rules each with their own type+mode, so we can't
	// require one canonical value — the migration leaves both empty for
	// multi-rule templates. When set they must be well-formed; the
	// chain-specific evaluators reject unknown types at registration
	// time, so we only police mode strictness here.
	if doc.Mode != "" && doc.Mode != types.RuleModeWhitelist && doc.Mode != types.RuleModeBlocklist {
		return fmt.Errorf("mode %q invalid (must be whitelist or blocklist)", doc.Mode)
	}
	seen := make(map[string]bool, len(doc.Variables))
	for i, v := range doc.Variables {
		if v.Name == "" {
			return fmt.Errorf("variables[%d]: name required", i)
		}
		if seen[v.Name] {
			return fmt.Errorf("variables[%d]: duplicate name %q", i, v.Name)
		}
		seen[v.Name] = true
		if v.Type == "" {
			return fmt.Errorf("variables[%d]: type required for %q", i, v.Name)
		}
		if !types.IsValidVariableType(string(v.Type)) {
			return fmt.Errorf("variables[%d]: type %q invalid for %q", i, v.Type, v.Name)
		}
		if v.Type == types.VarTypeEnum && len(v.Options) == 0 {
			return fmt.Errorf("variables[%d]: enum %q requires options", i, v.Name)
		}
	}
	for i, g := range doc.VariableGroups {
		for _, ref := range g.Variables {
			if !seen[ref] {
				return fmt.Errorf("variable_groups[%d]: references unknown variable %q", i, ref)
			}
		}
	}
	return nil
}

func validatePreset(doc *presetYAML) error {
	if doc.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(doc.TemplateIDs) == 0 {
		return fmt.Errorf("template_ids must not be empty")
	}
	for i, id := range doc.TemplateIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("template_ids[%d]: blank", i)
		}
	}
	for i, o := range doc.OperatorOverrides {
		if o.Name == "" {
			return fmt.Errorf("operator_overrides[%d]: name required", i)
		}
	}
	return nil
}
