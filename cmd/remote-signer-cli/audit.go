package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
)

// --- audit parent ---

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Query audit logs",
}

// --- audit list ---

var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit log records",
	RunE:  runAuditList,
}

var (
	flagAuditEventType     string
	flagAuditSeverity      string
	flagAuditAPIKeyID      string
	flagAuditSignerAddress string
	flagAuditChainType     string
	flagAuditChainID       string
	flagAuditStartTime     string
	flagAuditEndTime       string
	flagAuditLimit         int
	flagAuditCursor        string
	flagAuditCursorID      string
)

func runAuditList(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	filter := &audit.ListFilter{
		EventType:     flagAuditEventType,
		Severity:      flagAuditSeverity,
		APIKeyID:      flagAuditAPIKeyID,
		SignerAddress: flagAuditSignerAddress,
		ChainType:     flagAuditChainType,
		ChainID:       flagAuditChainID,
		Limit:         flagAuditLimit,
	}

	if flagAuditStartTime != "" {
		t, err := time.Parse(time.RFC3339, flagAuditStartTime)
		if err != nil {
			return fmt.Errorf("invalid --start-time %q (expected RFC3339): %w", flagAuditStartTime, err)
		}
		filter.StartTime = &t
	}
	if flagAuditEndTime != "" {
		t, err := time.Parse(time.RFC3339, flagAuditEndTime)
		if err != nil {
			return fmt.Errorf("invalid --end-time %q (expected RFC3339): %w", flagAuditEndTime, err)
		}
		filter.EndTime = &t
	}
	if flagAuditCursor != "" {
		filter.Cursor = &flagAuditCursor
	}
	if flagAuditCursorID != "" {
		filter.CursorID = &flagAuditCursorID
	}

	resp, err := c.Audit.List(cmd.Context(), filter)
	if err != nil {
		return fmt.Errorf("list audit records: %w", err)
	}

	if flagOutputFormat == "json" {
		return printJSON(resp)
	}

	fmt.Printf("Total: %d  HasMore: %v\n", resp.Total, resp.HasMore)
	printTable(
		[]string{"ID", "EVENT_TYPE", "SEVERITY", "TIMESTAMP", "API_KEY_ID", "ACTOR"},
		func() [][]string {
			rows := make([][]string, len(resp.Records))
			for i, r := range resp.Records {
				rows[i] = []string{
					r.ID, r.EventType, r.Severity,
					r.Timestamp.Format(time.RFC3339),
					r.APIKeyID, r.ActorAddress,
				}
			}
			return rows
		}(),
	)

	if resp.NextCursor != nil {
		fmt.Printf("\nNext cursor: %s\n", *resp.NextCursor)
	}
	if resp.NextCursorID != nil {
		fmt.Printf("Next cursor id: %s\n", *resp.NextCursorID)
	}
	return nil
}

// --- registration ---

func init() {
	auditListCmd.Flags().StringVar(&flagAuditEventType, "event-type", "", "Filter by event type")
	auditListCmd.Flags().StringVar(&flagAuditSeverity, "severity", "", "Filter by severity")
	auditListCmd.Flags().StringVar(&flagAuditAPIKeyID, "api-key-id", "", "Filter by API key ID")
	auditListCmd.Flags().StringVar(&flagAuditSignerAddress, "signer-address", "", "Filter by signer address")
	auditListCmd.Flags().StringVar(&flagAuditChainType, "chain-type", "", "Filter by chain type")
	auditListCmd.Flags().StringVar(&flagAuditChainID, "chain-id", "", "Filter by chain ID")
	auditListCmd.Flags().StringVar(&flagAuditStartTime, "start-time", "", "Filter from time (RFC3339)")
	auditListCmd.Flags().StringVar(&flagAuditEndTime, "end-time", "", "Filter until time (RFC3339)")
	auditListCmd.Flags().IntVar(&flagAuditLimit, "limit", 50, "Max results to return")
	auditListCmd.Flags().StringVar(&flagAuditCursor, "cursor", "", "Pagination cursor from previous response")
	auditListCmd.Flags().StringVar(&flagAuditCursorID, "cursor-id", "", "Pagination cursor id from previous response")

	auditCmd.AddCommand(auditListCmd)
}
