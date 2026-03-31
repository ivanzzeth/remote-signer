package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/pkg/client/templates"
)

// --- template parent ---

var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage rule templates via API",
}

// --- template list ---

var templateListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rule templates from server",
	RunE:  runTemplateList,
}

var (
	flagTemplateListType   string
	flagTemplateListSource string
	flagTemplateListLimit  int
	flagTemplateListOffset int
)

func runTemplateList(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	filter := &templates.ListFilter{
		Type:   flagTemplateListType,
		Source: flagTemplateListSource,
		Limit:  flagTemplateListLimit,
		Offset: flagTemplateListOffset,
	}

	resp, err := c.Templates.List(cmd.Context(), filter)
	if err != nil {
		return fmt.Errorf("list templates: %w", err)
	}

	if flagOutputFormat == "json" {
		return printJSON(resp)
	}

	fmt.Printf("Total: %d\n", resp.Total)
	printTable(
		[]string{"ID", "NAME", "TYPE", "MODE", "SOURCE", "ENABLED"},
		func() [][]string {
			rows := make([][]string, len(resp.Templates))
			for i, t := range resp.Templates {
				rows[i] = []string{
					t.ID, t.Name, t.Type, t.Mode, t.Source,
					strconv.FormatBool(t.Enabled),
				}
			}
			return rows
		}(),
	)
	return nil
}

// --- template get ---

var templateGetCmd = &cobra.Command{
	Use:   "get <template-id>",
	Short: "Get template details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		tmpl, err := c.Templates.Get(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("get template: %w", err)
		}
		return printJSON(tmpl)
	},
}

// --- template create ---

var templateCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a rule template from YAML/JSON file (admin only)",
	RunE:  runTemplateCreate,
}

var flagTemplateCreateFile string

func runTemplateCreate(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	cleanPath := filepath.Clean(flagTemplateCreateFile)
	data, err := os.ReadFile(cleanPath) // #nosec G304 -- user-provided CLI flag, path cleaned
	if err != nil {
		return fmt.Errorf("read file %s: %w", cleanPath, err)
	}

	var req templates.CreateRequest
	if err := yaml.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("unmarshal template definition: %w", err)
	}

	tmpl, err := c.Templates.Create(cmd.Context(), &req)
	if err != nil {
		return fmt.Errorf("create template: %w", err)
	}
	return printJSON(tmpl)
}

// --- template update ---

var templateUpdateCmd = &cobra.Command{
	Use:   "update <template-id>",
	Short: "Update a rule template from YAML/JSON file (admin only)",
	Args:  cobra.ExactArgs(1),
	RunE:  runTemplateUpdate,
}

var flagTemplateUpdateFile string

func runTemplateUpdate(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	cleanPath := filepath.Clean(flagTemplateUpdateFile)
	data, err := os.ReadFile(cleanPath) // #nosec G304 -- user-provided CLI flag, path cleaned
	if err != nil {
		return fmt.Errorf("read file %s: %w", cleanPath, err)
	}

	var req templates.UpdateRequest
	if err := yaml.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("unmarshal template update: %w", err)
	}

	tmpl, err := c.Templates.Update(cmd.Context(), args[0], &req)
	if err != nil {
		return fmt.Errorf("update template: %w", err)
	}
	return printJSON(tmpl)
}

// --- template delete ---

var templateDeleteCmd = &cobra.Command{
	Use:   "delete <template-id>",
	Short: "Delete a rule template (admin only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.Templates.Delete(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("delete template: %w", err)
		}
		fmt.Printf("Template %s deleted\n", args[0])
		return nil
	},
}

// --- template instantiate ---

var templateInstantiateCmd = &cobra.Command{
	Use:   "instantiate <template-id>",
	Short: "Create a rule instance from a template (admin only)",
	Args:  cobra.ExactArgs(1),
	RunE:  runTemplateInstantiate,
}

var flagTemplateInstantiateFile string

func runTemplateInstantiate(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	cleanPath := filepath.Clean(flagTemplateInstantiateFile)
	data, err := os.ReadFile(cleanPath) // #nosec G304 -- user-provided CLI flag, path cleaned
	if err != nil {
		return fmt.Errorf("read file %s: %w", cleanPath, err)
	}

	var req templates.InstantiateRequest
	if err := yaml.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("unmarshal instantiate request: %w", err)
	}

	resp, err := c.Templates.Instantiate(cmd.Context(), args[0], &req)
	if err != nil {
		return fmt.Errorf("instantiate template: %w", err)
	}
	return printJSON(resp)
}

// --- template revoke-instance ---

var templateRevokeInstanceCmd = &cobra.Command{
	Use:   "revoke-instance <rule-id>",
	Short: "Revoke a rule instance created from a template (admin only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.Templates.RevokeInstance(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("revoke instance: %w", err)
		}
		return printJSON(resp)
	},
}

// --- registration ---

func init() {
	// list flags
	templateListCmd.Flags().StringVar(&flagTemplateListType, "type", "", "Filter by template type")
	templateListCmd.Flags().StringVar(&flagTemplateListSource, "source", "", "Filter by source")
	templateListCmd.Flags().IntVar(&flagTemplateListLimit, "limit", 50, "Max results to return")
	templateListCmd.Flags().IntVar(&flagTemplateListOffset, "offset", 0, "Offset for pagination")

	// create flags
	templateCreateCmd.Flags().StringVarP(&flagTemplateCreateFile, "file", "f", "", "Path to YAML/JSON template definition")
	if err := templateCreateCmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	// update flags
	templateUpdateCmd.Flags().StringVarP(&flagTemplateUpdateFile, "file", "f", "", "Path to YAML/JSON template update")
	if err := templateUpdateCmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	// instantiate flags
	templateInstantiateCmd.Flags().StringVarP(&flagTemplateInstantiateFile, "file", "f", "", "Path to YAML/JSON instantiate request")
	if err := templateInstantiateCmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	templateCmd.AddCommand(templateListCmd)
	templateCmd.AddCommand(templateGetCmd)
	templateCmd.AddCommand(templateCreateCmd)
	templateCmd.AddCommand(templateUpdateCmd)
	templateCmd.AddCommand(templateDeleteCmd)
	templateCmd.AddCommand(templateInstantiateCmd)
	templateCmd.AddCommand(templateRevokeInstanceCmd)
}
