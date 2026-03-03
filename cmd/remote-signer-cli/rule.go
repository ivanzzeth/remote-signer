package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "List templates/presets, or create a rule from a preset",
	Long:  "Subcommands: list-templates (from config), list-presets (from rules/presets/), create-from-preset (output YAML or merge into config).",
}

var (
	ruleListTemplatesConfig string
	ruleListPresetsDir     string
	ruleCreatePresetsDir   string
	ruleCreateConfig       string
	ruleCreateWrite        bool
	ruleCreateSet          []string
)

func init() {
	ruleCmd.AddCommand(ruleListTemplatesCmd)
	ruleCmd.AddCommand(ruleListPresetsCmd)
	ruleCmd.AddCommand(ruleCreateFromPresetCmd)

	ruleListTemplatesCmd.Flags().StringVarP(&ruleListTemplatesConfig, "config", "c", "config.yaml", "Path to config file")
	ruleListPresetsCmd.Flags().StringVar(&ruleListPresetsDir, "presets-dir", "rules/presets", "Directory containing preset YAML files")
	ruleCreateFromPresetCmd.Flags().StringVar(&ruleCreatePresetsDir, "presets-dir", "rules/presets", "Directory containing preset YAML files")
	ruleCreateFromPresetCmd.Flags().StringVar(&ruleCreateConfig, "config", "", "Config file to merge into (requires --write)")
	ruleCreateFromPresetCmd.Flags().BoolVar(&ruleCreateWrite, "write", false, "Merge generated rule(s) into config (requires --config)")
	ruleCreateFromPresetCmd.Flags().StringArrayVar(&ruleCreateSet, "set", nil, "Override variable (key=value)")
}

var ruleListTemplatesCmd = &cobra.Command{
	Use:   "list-templates",
	Short: "List templates from config",
	RunE:  runRuleListTemplatesCobra,
}

var ruleListPresetsCmd = &cobra.Command{
	Use:   "list-presets",
	Short: "List presets from rules/presets/ (or --presets-dir)",
	RunE:  runRuleListPresetsCobra,
}

var ruleCreateFromPresetCmd = &cobra.Command{
	Use:   "create-from-preset [preset-name]",
	Short: "Create rule YAML from preset; use --config and --write to merge into config",
	Args:  cobra.ExactArgs(1),
	RunE:  runRuleCreateFromPresetCobra,
}

func runRuleListTemplatesCobra(cmd *cobra.Command, args []string) error {
	configDir := filepath.Dir(ruleListTemplatesConfig)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg, err := config.Load(ruleListTemplatesConfig)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	templates, err := config.ExpandTemplatesFromFiles(cfg.Templates, configDir, log)
	if err != nil {
		return fmt.Errorf("expand templates: %w", err)
	}

	fmt.Println("# Template name | path (if file) | variable names")
	for _, t := range templates {
		path := ""
		if t.Config != nil {
			if p, _ := t.Config["path"].(string); p != "" {
				path = p
			}
		}
		varNames := ""
		for i, v := range t.Variables {
			if i > 0 {
				varNames += ", "
			}
			varNames += v.Name
		}
		fmt.Printf("%s | %s | %s\n", t.Name, path, varNames)
	}
	return nil
}

func runRuleListPresetsCobra(cmd *cobra.Command, args []string) error {
	entries, err := os.ReadDir(ruleListPresetsDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("# No presets directory found at", ruleListPresetsDir)
			return nil
		}
		return fmt.Errorf("read presets dir: %w", err)
	}

	fmt.Println("# Preset file | template(s)")
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" && filepath.Ext(e.Name()) != ".yml" {
			continue
		}
		path := filepath.Join(ruleListPresetsDir, e.Name())
		templates, err := presetTemplateNames(path)
		if err != nil {
			fmt.Printf("%s | (error: %v)\n", e.Name(), err)
			continue
		}
		fmt.Printf("%s | %s\n", e.Name(), templates)
	}
	return nil
}

func runRuleCreateFromPresetCobra(cmd *cobra.Command, args []string) error {
	presetName := args[0]
	overrides := setStringsToMap(ruleCreateSet)

	path := filepath.Join(ruleCreatePresetsDir, presetName)
	if filepath.Ext(path) == "" {
		path += ".yaml"
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path from trusted presets-dir + user preset name
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

	if ruleCreateWrite {
		if ruleCreateConfig == "" {
			return fmt.Errorf("--write requires --config")
		}
		return mergeRulesIntoConfig(ruleCreateConfig, rules)
	}

	out := struct {
		Rules []config.RuleConfig `yaml:"rules"`
	}{Rules: rules}
	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	return enc.Encode(out)
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

// presetTemplateNames reads a preset file and returns a comma-separated list of template names (for listing).
func presetTemplateNames(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from trusted presets-dir
	if err != nil {
		return "", err
	}
	var single struct {
		Template string `yaml:"template"`
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

// parsePresetFile parses preset YAML (single-rule or multi-rule) and returns RuleConfig slice.
// Applies overrides to variables. Variables in preset can be scalar or array; we normalize
// arrays to comma-separated strings for config so server's fillInMappingArrays works.
func parsePresetFile(data []byte, overrides map[string]string) ([]config.RuleConfig, error) {
	var single struct {
		Name      string                 `yaml:"name"`
		Template  string                 `yaml:"template"`
		ChainType string                 `yaml:"chain_type"`
		ChainID   string                 `yaml:"chain_id"`
		Enabled   bool                   `yaml:"enabled"`
		Variables map[string]interface{} `yaml:"variables"`
	}
	if err := yaml.Unmarshal(data, &single); err != nil {
		return nil, err
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

// toMapStringInterface converts variables from YAML (often map[interface{}]interface{}) to map[string]interface{}.
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

// normalizeVariables converts map values so arrays become comma-separated strings (for in_mapping_arrays).
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

// mergeRulesIntoConfig appends rules to config's rules array and writes back.
func mergeRulesIntoConfig(configPath string, rules []config.RuleConfig) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
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
