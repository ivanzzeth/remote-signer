package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/preset"
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
	entries, err := preset.ListPresets(presetListDir)
	if err != nil {
		return fmt.Errorf("list presets: %w", err)
	}
	if entries == nil {
		fmt.Println("# No presets directory found at", presetListDir)
		return nil
	}
	fmt.Println("# Preset file | template(s)")
	for _, e := range entries {
		templates := strings.Join(e.TemplateNames, ", ")
		fmt.Printf("%s | %s\n", e.ID, templates)
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

	presetRules, err := preset.ParsePresetFile(data, overrides)
	if err != nil {
		return fmt.Errorf("parse preset: %w", err)
	}
	if len(presetRules) == 0 {
		return fmt.Errorf("preset produced no rules")
	}
	rules := make([]config.RuleConfig, 0, len(presetRules))
	for _, pr := range presetRules {
		rules = append(rules, presetRuleToRuleConfig(pr))
	}

	if presetCreateWrite {
		if presetCreateConfig == "" {
			return fmt.Errorf("--write requires --config")
		}
		meta, err := preset.GetPresetMeta(data)
		if err != nil {
			return fmt.Errorf("parse preset meta: %w", err)
		}
		if len(meta.TemplatePaths) > 0 && len(meta.TemplateNames) > 0 {
			return mergeCompositePresetIntoConfig(presetCreateConfig, rules, meta.TemplatePaths, meta.TemplateNames)
		}
		return mergeRulesAndTemplateIntoConfig(presetCreateConfig, rules, meta.Template, meta.TemplatePath)
	}

	out := struct {
		Rules []config.RuleConfig `yaml:"rules"`
	}{Rules: rules}
	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	return enc.Encode(out)
}

// presetRuleToRuleConfig converts a preset.PresetRule to config.RuleConfig for merge or YAML output.
func presetRuleToRuleConfig(pr preset.PresetRule) config.RuleConfig {
	variables := make(map[string]interface{})
	for k, v := range pr.Variables {
		variables[k] = v
	}
	cfg := map[string]interface{}{"template": pr.TemplateName, "variables": variables}
	if len(pr.Budget) > 0 {
		cfg["budget"] = pr.Budget
	}
	if len(pr.Schedule) > 0 {
		cfg["schedule"] = pr.Schedule
	}
	mode := pr.Mode
	if mode == "" {
		mode = "whitelist"
	}
	return config.RuleConfig{
		Name:      pr.Name,
		Type:      "instance",
		Mode:      mode,
		ChainType: pr.ChainType,
		ChainID:   pr.ChainID,
		Enabled:   pr.Enabled,
		Config:    cfg,
	}
}

// mergeRulesAndTemplateIntoConfig appends rules to config; if templateName and templatePath are set and config
// does not already define that template, appends a template entry from the preset (so preset is self-contained).
func mergeRulesAndTemplateIntoConfig(configPath string, rules []config.RuleConfig, templateName, templatePath string) error {
	return mergeCompositePresetIntoConfig(configPath, rules, []string{templatePath}, []string{templateName})
}

// mergeCompositePresetIntoConfig replaces rules matching the preset's base name, then appends the new rules.
// Injects each (templatePath, templateName) into config if missing.
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
	// Replace rules that match the preset's rule names (same base name), then append new rules
	if len(rules) > 0 {
		baseName := rules[0].Name
		if idx := strings.LastIndex(baseName, " ("); idx > 0 {
			baseName = baseName[:idx]
		}
		filtered := cfg.Rules[:0]
		for _, r := range cfg.Rules {
			if r.Name == baseName || strings.HasPrefix(r.Name, baseName+" (") {
				continue
			}
			filtered = append(filtered, r)
		}
		cfg.Rules = append(filtered, rules...)
	} else {
		cfg.Rules = append(cfg.Rules, rules...)
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, out, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
		fmt.Fprintf(os.Stderr, "Updated rules in %s (%d rule(s) from preset)\n", configPath, len(rules))
	return nil
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
	meta, err := preset.GetPresetMeta(data)
	if err != nil {
		return nil, fmt.Errorf("parse preset meta: %w", err)
	}
	if len(meta.OverrideHints) == 0 {
		return nil, nil
	}
	descriptions := make(map[string]string)
	pathsToRead := []string{meta.TemplatePath}
	if meta.TemplatePath == "" && len(meta.TemplatePaths) > 0 {
		pathsToRead = meta.TemplatePaths
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
	out := make([]presetVarDesc, 0, len(meta.OverrideHints))
	for _, name := range meta.OverrideHints {
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
