package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

var presetCmd = &cobra.Command{
	Use:   "preset",
	Short: "List presets or create rules from a preset",
	Long:  "Subcommands: list (presets in rules/presets/), create-from (output rule YAML or merge into config with --write).",
}

var (
	presetListDir      string
	presetCreateDir    string
	presetCreateConfig string
	presetCreateWrite  bool
	presetCreateSet    []string
	presetVarsDir      string
	presetVarsProject  string
)

func init() {
	presetCmd.AddCommand(presetListCmd)
	presetCmd.AddCommand(presetCreateFromCmd)
	presetCmd.AddCommand(presetVarsCmd)

	presetListCmd.Flags().StringVar(&presetListDir, "presets-dir", "rules/presets", "Directory containing preset YAML files")
	presetCreateFromCmd.Flags().StringVar(&presetCreateDir, "presets-dir", "rules/presets", "Directory containing preset YAML files")
	presetCreateFromCmd.Flags().StringVar(&presetCreateConfig, "config", "", "Config file to merge into (requires --write)")
	presetCreateFromCmd.Flags().BoolVar(&presetCreateWrite, "write", false, "Merge generated rule(s) into config (requires --config)")
	presetCreateFromCmd.Flags().StringArrayVar(&presetCreateSet, "set", nil, "Override variable (key=value)")
	presetVarsCmd.Flags().StringVar(&presetVarsDir, "presets-dir", "rules/presets", "Directory containing preset YAML files")
	presetVarsCmd.Flags().StringVar(&presetVarsProject, "project-dir", ".", "Project root (for resolving template_path when reading variable descriptions)")
}

var presetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List presets from rules/presets/ (or --presets-dir)",
	RunE:  runPresetList,
}

var presetCreateFromCmd = &cobra.Command{
	Use:   "create-from [preset-name]",
	Short: "Create rule YAML from preset; use --config and --write to merge into config (injects template from preset template_path if missing)",
	Args:  cobra.ExactArgs(1),
	RunE:  runPresetCreateFrom,
}

var presetVarsCmd = &cobra.Command{
	Use:   "vars [preset-name]",
	Short: "Output variables to prompt (override_hints) with descriptions from template (for setup scripts)",
	Long:  "Prints one line per variable: name<TAB>description. Use with preset's template_path to show descriptions from the template file.",
	Args:  cobra.ExactArgs(1),
	RunE:  runPresetVars,
}

func runPresetList(cmd *cobra.Command, args []string) error {
	entries, err := os.ReadDir(presetListDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("# No presets directory found at", presetListDir)
			return nil
		}
		return fmt.Errorf("read presets dir: %w", err)
	}

	fmt.Println("# Preset file | template(s)")
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" && filepath.Ext(e.Name()) != ".yml" {
			continue
		}
		path := filepath.Join(presetListDir, e.Name())
		templates, err := presetTemplateNames(path)
		if err != nil {
			fmt.Printf("%s | (error: %v)\n", e.Name(), err)
			continue
		}
		fmt.Printf("%s | %s\n", e.Name(), templates)
	}
	return nil
}

func runPresetCreateFrom(cmd *cobra.Command, args []string) error {
	presetName := args[0]
	overrides := setStringsToMap(presetCreateSet)

	path := filepath.Join(presetCreateDir, presetName)
	if filepath.Ext(path) == "" {
		path += ".yaml"
	}
	tryPaths := []string{path}
	if filepath.Ext(path) == ".preset" {
		tryPaths = append(tryPaths, path+".yaml")
	}
	if filepath.Ext(path) == ".yaml" && !strings.HasSuffix(path, ".preset.yaml") {
		tryPaths = append(tryPaths, strings.TrimSuffix(path, ".yaml")+".preset.yaml")
	}
	var data []byte
	var err error
	for _, p := range tryPaths {
		data, err = os.ReadFile(p) // #nosec G304 -- path from trusted presets-dir + user preset name
		if err == nil {
			path = p
			break
		}
	}
	if err != nil {
		return fmt.Errorf("read preset %s: %w", path, err)
	}

	rules, err := parsePresetFile(data, overrides)
	if err != nil {
		return fmt.Errorf("parse preset: %w", err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("preset produced no rules")
	}

	if presetCreateWrite {
		if presetCreateConfig == "" {
			return fmt.Errorf("--write requires --config")
		}
		meta := getPresetMeta(data)
		if len(meta.templatePaths) > 0 && len(meta.templateNames) > 0 {
			return mergeCompositePresetIntoConfig(presetCreateConfig, rules, meta.templatePaths, meta.templateNames)
		}
		return mergeRulesAndTemplateIntoConfig(presetCreateConfig, rules, meta.template, meta.templatePath)
	}

	out := struct {
		Rules []config.RuleConfig `yaml:"rules"`
	}{Rules: rules}
	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	return enc.Encode(out)
}

// presetMeta holds template name(s), path(s), and override hints from a preset file.
type presetMeta struct {
	template       string
	templatePath   string
	templatePaths  []string
	templateNames  []string
	overrideHints  []string
}

// getPresetMeta parses preset YAML and returns template name(s), template_path(s), and override_hints.
// Supports single-rule (template + template_path) and composite (template_paths + template_names) presets.
func getPresetMeta(data []byte) presetMeta {
	var out presetMeta
	var single struct {
		Template      string   `yaml:"template"`
		TemplatePath  string   `yaml:"template_path"`
		TemplatePaths []string `yaml:"template_paths"`
		TemplateNames []string `yaml:"template_names"`
		OverrideHints []string `yaml:"override_hints"`
	}
	if err := yaml.Unmarshal(data, &single); err != nil {
		return out
	}
	out.template = single.Template
	out.templatePath = single.TemplatePath
	out.templatePaths = single.TemplatePaths
	out.templateNames = single.TemplateNames
	out.overrideHints = single.OverrideHints
	if out.overrideHints == nil {
		out.overrideHints = []string{}
	}
	return out
}

// mergeRulesAndTemplateIntoConfig appends rules to config; if templateName and templatePath are set and config
// does not already define that template, appends a template entry from the preset (so preset is self-contained).
func mergeRulesAndTemplateIntoConfig(configPath string, rules []config.RuleConfig, templateName, templatePath string) error {
	return mergeCompositePresetIntoConfig(configPath, rules, []string{templatePath}, []string{templateName})
}

// mergeCompositePresetIntoConfig appends rules and injects each (templatePath, templateName) into config if missing.
func mergeCompositePresetIntoConfig(configPath string, rules []config.RuleConfig, templatePaths, templateNames []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	n := len(templatePaths)
	if len(templateNames) < n {
		n = len(templateNames)
	}
	for i := 0; i < n; i++ {
		name, path := templateNames[i], templatePaths[i]
		if name == "" || path == "" {
			continue
		}
		hasTemplate := false
		for j := range cfg.Templates {
			if cfg.Templates[j].Name == name {
				hasTemplate = true
				break
			}
		}
		if !hasTemplate {
			cfg.Templates = append(cfg.Templates, config.TemplateConfig{
				Name:    name,
				Type:    "file",
				Enabled: true,
				Config:  map[string]interface{}{"path": path},
			})
			fmt.Fprintf(os.Stderr, "Injected template %q (path: %s) into config\n", name, path)
		}
	}
	cfg.Rules = append(cfg.Rules, rules...)
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, out, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Appended %d rule(s) to %s\n", len(rules), configPath)
	return nil
}

// presetTemplateNames reads a preset file and returns a comma-separated list of template names (for listing).
func presetTemplateNames(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from trusted presets-dir
	if err != nil {
		return "", err
	}
	var single struct {
		Template     string   `yaml:"template"`
		TemplateNames []string `yaml:"template_names"`
	}
	var multi struct {
		Rules []struct {
			Config struct {
				Template string `yaml:"template"`
			} `yaml:"config"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &single); err != nil {
		return "", err
	}
	if single.Template != "" {
		return single.Template, nil
	}
	if len(single.TemplateNames) > 0 {
		return strings.Join(single.TemplateNames, ", "), nil
	}
	if err := yaml.Unmarshal(data, &multi); err != nil {
		return "", err
	}
	var names string
	for i, r := range multi.Rules {
		if i > 0 {
			names += ", "
		}
		names += r.Config.Template
	}
	return names, nil
}

// parsePresetFile parses preset YAML (single-rule, composite template_paths, or multi-rule) and returns RuleConfig slice.
// Applies overrides to variables. Variables in preset can be scalar or array; we normalize
// arrays to comma-separated strings for config so server's fillInMappingArrays works.
func parsePresetFile(data []byte, overrides map[string]string) ([]config.RuleConfig, error) {
	var single struct {
		Name          string                 `yaml:"name"`
		Template      string                 `yaml:"template"`
		TemplatePath  string                 `yaml:"template_path"`
		TemplatePaths []string               `yaml:"template_paths"`
		TemplateNames []string               `yaml:"template_names"`
		ChainType     string                 `yaml:"chain_type"`
		ChainID       string                 `yaml:"chain_id"`
		Enabled       bool                   `yaml:"enabled"`
		Variables     map[string]interface{} `yaml:"variables"`
	}
	if err := yaml.Unmarshal(data, &single); err != nil {
		return nil, err
	}
	// Composite preset: one rule per (template_paths[i], template_names[i])
	if len(single.TemplatePaths) > 0 && len(single.TemplateNames) > 0 {
		n := len(single.TemplatePaths)
		if len(single.TemplateNames) < n {
			n = len(single.TemplateNames)
		}
		variables := normalizeVariables(single.Variables)
		if variables == nil {
			variables = make(map[string]interface{})
		}
		for k, v := range overrides {
			variables[k] = v
		}
		rules := make([]config.RuleConfig, 0, n)
		baseName := single.Name
		if baseName == "" {
			baseName = "Polymarket"
		}
		for i := 0; i < n; i++ {
			templateName := single.TemplateNames[i]
			if templateName == "" {
				continue
			}
			ruleName := baseName
			if n > 1 {
				ruleName = baseName + " (" + templateName + ")"
			}
			rules = append(rules, config.RuleConfig{
				Name:      ruleName,
				Type:      "instance",
				Mode:      "whitelist",
				ChainType: single.ChainType,
				ChainID:   single.ChainID,
				Enabled:   single.Enabled,
				Config:    map[string]interface{}{"template": templateName, "variables": copyMapInterface(variables)},
			})
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("composite preset produced no rules (template_paths/template_names)")
		}
		return rules, nil
	}
	if single.Template != "" {
		variables := normalizeVariables(single.Variables)
		for k, v := range overrides {
			variables[k] = v
		}
		r := config.RuleConfig{
			Name:      single.Name,
			Type:      "instance",
			Mode:      "whitelist",
			ChainType: single.ChainType,
			ChainID:   single.ChainID,
			Enabled:   single.Enabled,
			Config:    map[string]interface{}{"template": single.Template, "variables": variables},
		}
		return []config.RuleConfig{r}, nil
	}

	var multi struct {
		Rules []config.RuleConfig `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &multi); err != nil {
		return nil, err
	}
	if len(multi.Rules) == 0 {
		return nil, fmt.Errorf("preset has no rules and no single-rule fields")
	}
	for i := range multi.Rules {
		vars := toMapStringInterface(multi.Rules[i].Config["variables"])
		if vars == nil {
			vars = make(map[string]interface{})
		}
		vars = normalizeVariables(vars)
		for k, v := range overrides {
			vars[k] = v
		}
		multi.Rules[i].Config["variables"] = vars
	}
	return multi.Rules, nil
}

func copyMapInterface(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func toMapStringInterface(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	if m, ok := v.(map[interface{}]interface{}); ok {
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			if s, ok := k.(string); ok {
				out[s] = val
			}
		}
		return out
	}
	return nil
}

func normalizeVariables(v map[string]interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	out := make(map[string]interface{}, len(v))
	for k, val := range v {
		switch t := val.(type) {
		case []interface{}:
			var parts []string
			for _, p := range t {
				parts = append(parts, fmt.Sprintf("%v", p))
			}
			out[k] = strings.Join(parts, ",")
		default:
			out[k] = val
		}
	}
	return out
}

// setStringsToMap converts key=value strings (e.g. from --set) to a map.
func setStringsToMap(s []string) map[string]string {
	out := make(map[string]string)
	for _, v := range s {
		for i := 0; i < len(v); i++ {
			if v[i] == '=' {
				out[v[:i]] = v[i+1:]
				break
			}
		}
	}
	return out
}

// templateFileVars is the variables section of a template file (for reading descriptions).
type templateFileVars struct {
	Variables []struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"variables"`
}

// presetVarDesc is a variable name and its description (from template).
type presetVarDesc struct {
	Name string
	Desc string
}

// getPresetVarsWithDescriptions reads the preset at presetPath and returns override_hints with
// descriptions from template file(s) (projectDir + preset's template_path or template_paths). Used by runPresetVars and tests.
func getPresetVarsWithDescriptions(presetPath, projectDir string) ([]presetVarDesc, error) {
	data, err := os.ReadFile(presetPath) // #nosec G304 -- path from caller (tests or trusted presets-dir)
	if err != nil {
		return nil, err
	}
	meta := getPresetMeta(data)
	if len(meta.overrideHints) == 0 {
		return nil, nil
	}
	descriptions := make(map[string]string)
	pathsToRead := []string{meta.templatePath}
	if meta.templatePath == "" && len(meta.templatePaths) > 0 {
		pathsToRead = meta.templatePaths
	}
	for _, p := range pathsToRead {
		if p == "" {
			continue
		}
		templatePath := filepath.Join(projectDir, p)
		templateData, err := os.ReadFile(templatePath) // #nosec G304 -- path from preset + trusted project-dir
		if err != nil {
			continue
		}
		var tv templateFileVars
		if err := yaml.Unmarshal(templateData, &tv); err != nil {
			continue
		}
		for _, v := range tv.Variables {
			if _, ok := descriptions[v.Name]; !ok {
				descriptions[v.Name] = v.Description
			}
		}
	}
	out := make([]presetVarDesc, 0, len(meta.overrideHints))
	for _, name := range meta.overrideHints {
		out = append(out, presetVarDesc{Name: name, Desc: descriptions[name]})
	}
	return out, nil
}

func runPresetVars(cmd *cobra.Command, args []string) error {
	presetName := args[0]
	path := filepath.Join(presetVarsDir, presetName)
	if filepath.Ext(path) == "" {
		path += ".yaml"
	}
	tryPaths := []string{path}
	if filepath.Ext(path) == ".preset" {
		tryPaths = append(tryPaths, path+".yaml")
	}
	if filepath.Ext(path) == ".yaml" && !strings.HasSuffix(path, ".preset.yaml") {
		tryPaths = append(tryPaths, strings.TrimSuffix(path, ".yaml")+".preset.yaml")
	}
	var vars []presetVarDesc
	var err error
	for _, p := range tryPaths {
		vars, err = getPresetVarsWithDescriptions(p, presetVarsProject)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("read preset %s: %w", path, err)
	}
	for _, v := range vars {
		fmt.Printf("%s\t%s\n", v.Name, v.Desc)
	}
	return nil
}
