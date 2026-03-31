package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// --- acl parent ---

var aclCmd = &cobra.Command{
	Use:   "acl",
	Short: "View ACL configuration (admin only)",
}

// --- acl ip-whitelist ---

var aclIPWhitelistCmd = &cobra.Command{
	Use:   "ip-whitelist",
	Short: "Show IP whitelist configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.ACLs.GetIPWhitelist(cmd.Context())
		if err != nil {
			return fmt.Errorf("get ip whitelist: %w", err)
		}
		return printJSON(resp)
	},
}

// --- registration ---

func init() {
	aclCmd.AddCommand(aclIPWhitelistCmd)
}
