package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
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
		resp, err := c.Presets.ApplyWithVariables(context.Background(), presetName, variables)
		if err != nil {
			return fmt.Errorf("failed to apply preset %q: %w", presetName, err)
		}

		fmt.Printf("Preset %q applied successfully.\n", presetName)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	},
}

var presetApplySetFlags []string

func init() {
	presetApplyCmd.Flags().StringArrayVar(&presetApplySetFlags, "set", nil, "Variable override (key=value, repeatable)")
	presetCmd.AddCommand(presetApplyCmd)
}
