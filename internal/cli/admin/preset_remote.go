package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/presets"
	"github.com/spf13/cobra"
)

var (
	presetApplySetFlags       []string
	presetApplyAppliedToFlags []string
	presetApplySkipValidation bool
	presetValidateSetFlags    []string
)

var presetApplyCmd = &cobra.Command{
	Use:   "apply <preset-name>",
	Short: "Apply a preset via server API (creates rules with proper RBAC ownership)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		variables := make(map[string]string)
		for _, s := range presetApplySetFlags {
			parts := strings.SplitN(s, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid --set format %q, expected key=value", s)
			}
			variables[parts[0]] = parts[1]
		}

		presetName := args[0]
		req := &presets.ApplyRequest{
			Variables:      variables,
			AppliedTo:      presetApplyAppliedToFlags,
			SkipValidation: presetApplySkipValidation,
		}
		resp, err := c.Presets.Apply(cmd.Context(), presetName, req)
		if err != nil {
			return fmt.Errorf("failed to apply preset %q: %w", presetName, err)
		}

		fmt.Printf("Preset %q applied successfully.\n", presetName)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	},
}

// --- preset validate ---

var presetValidateCmd = &cobra.Command{
	Use:   "validate <preset-id>",
	Short: "Validate a preset's test cases with optional variable overrides",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		variables := make(map[string]string)
		for _, s := range presetValidateSetFlags {
			parts := strings.SplitN(s, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid --set format %q, expected key=value", s)
			}
			variables[parts[0]] = parts[1]
		}

		resp, err := c.Presets.Validate(cmd.Context(), args[0], variables)
		if err != nil {
			return fmt.Errorf("validate preset: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(resp)
		}
		fmt.Printf("Preset: %s [%s]\n", resp.PresetID, resp.PresetName)
		fmt.Printf("Total: %d  Passed: %d  Failed: %d\n", resp.Total, resp.Passed, resp.Failed)
		for _, r := range resp.Results {
			status := "PASS"
			if !r.Valid {
				status = "FAIL"
			}
			fmt.Printf("  %s [%s] %s\n", status, r.Type, r.RuleName)
			if r.Error != "" {
				fmt.Printf("    error: %s\n", r.Error)
			}
		}
		return nil
	},
}

// --- preset remote-list ---

var presetRemoteListCmd = &cobra.Command{
	Use:   "remote-list",
	Short: "List presets from server API",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		resp, err := c.Presets.List(cmd.Context())
		if err != nil {
			return fmt.Errorf("list presets: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		fmt.Printf("Total: %d\n", len(resp.Presets))
		printTable(
			[]string{"ID", "NAME", "CHAIN", "TEMPLATES", "ENABLED"},
			func() [][]string {
				rows := make([][]string, len(resp.Presets))
				for i, p := range resp.Presets {
					chain := p.ChainType
					if p.ChainID != "" {
						chain = chain + "/" + p.ChainID
					}
					rows[i] = []string{
						p.ID, p.Name, chain,
						strings.Join(p.TemplateIDs, ","),
						strconv.FormatBool(p.Enabled),
					}
				}
				return rows
			}(),
		)
		return nil
	},
}

// --- preset remote-get ---

var presetRemoteGetCmd = &cobra.Command{
	Use:   "remote-get <preset-id>",
	Short: "Get preset details with variable descriptions from server API",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		resp, err := c.Presets.Get(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("get preset: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		fmt.Printf("ID:          %s\n", resp.ID)
		fmt.Printf("Name:        %s\n", resp.Name)
		fmt.Printf("Description: %s\n", resp.Description)
		fmt.Printf("Chain:       %s/%s\n", resp.ChainType, resp.ChainID)
		fmt.Printf("Enabled:     %v\n", resp.Enabled)
		fmt.Printf("Templates:   %s\n", strings.Join(resp.TemplateIDs, ", "))
		fmt.Println()
		if len(resp.Variables) > 0 {
			fmt.Printf("Variables:\n")
			printTable(
				[]string{"NAME", "TYPE", "REQUIRED", "DEFAULT", "DESCRIPTION"},
				func() [][]string {
					rows := make([][]string, len(resp.Variables))
					for i, v := range resp.Variables {
						rows[i] = []string{
							v.Name, v.Type,
							strconv.FormatBool(v.Required),
							v.DefaultValue,
							v.Description,
						}
					}
					return rows
				}(),
			)
		}
		return nil
	},
}

func init() {
	presetApplyCmd.Flags().StringArrayVar(&presetApplySetFlags, "set", nil, "Variable override (key=value, repeatable)")
	presetApplyCmd.Flags().StringSliceVar(&presetApplyAppliedToFlags, "applied-to", nil, "Scope rules to specific API key IDs (comma-separated or repeatable)")
	presetApplyCmd.Flags().BoolVar(&presetApplySkipValidation, "skip-validation", false, "Skip test case validation on apply")
	presetCmd.AddCommand(presetApplyCmd)

	presetValidateCmd.Flags().StringArrayVar(&presetValidateSetFlags, "set", nil, "Variable override (key=value, repeatable)")
	presetCmd.AddCommand(presetValidateCmd)

	presetCmd.AddCommand(presetRemoteListCmd)
	presetCmd.AddCommand(presetRemoteGetCmd)
}
