package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "List templates from config",
	Long:  "Subcommands: list-templates (from config file).",
}

var ruleListTemplatesConfig string

func init() {
	ruleCmd.AddCommand(ruleListTemplatesCmd)
	ruleListTemplatesCmd.Flags().StringVarP(&ruleListTemplatesConfig, "config", "c", "config.yaml", "Path to config file")
}

var ruleListTemplatesCmd = &cobra.Command{
	Use:   "list-templates",
	Short: "List templates from config",
	RunE:  runRuleListTemplatesCobra,
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
