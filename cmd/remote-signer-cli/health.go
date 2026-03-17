package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check server health",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.Health(context.Background())
		if err != nil {
			return fmt.Errorf("health check failed: %w", err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	},
}
