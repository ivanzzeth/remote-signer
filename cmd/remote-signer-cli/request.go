package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/spf13/cobra"
)

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Manage signing requests (list, get, approve, reject)",
}

// ── request list ────────────────────────────────────────────────────────────

var (
	reqListStatus  string
	reqListSigner  string
	reqListChainID string
	reqListLimit   int
)

var requestListCmd = &cobra.Command{
	Use:   "list",
	Short: "List signing requests with optional filters",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		filter := &evm.ListRequestsFilter{
			Status:        reqListStatus,
			SignerAddress: reqListSigner,
			ChainID:       reqListChainID,
			Limit:         reqListLimit,
		}

		resp, err := c.EVM.Requests.List(context.Background(), filter)
		if err != nil {
			return fmt.Errorf("list requests failed: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		if len(resp.Requests) == 0 {
			fmt.Println("No requests found.")
			return nil
		}

		fmt.Printf("Total: %d\n", resp.Total)
		headers := []string{"ID", "STATUS", "SIGNER", "CHAIN", "TYPE", "API_KEY", "CREATED"}
		var rows [][]string
		for _, r := range resp.Requests {
			rows = append(rows, []string{
				r.ID,
				r.Status,
				r.SignerAddress,
				r.ChainID,
				r.SignType,
				r.APIKeyID,
				r.CreatedAt.Format(time.RFC3339),
			})
		}
		printTable(headers, rows)
		return nil
	},
}

// ── request get ─────────────────────────────────────────────────────────────

var requestGetCmd = &cobra.Command{
	Use:   "get <request-id>",
	Short: "Get details of a signing request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		resp, err := c.EVM.Requests.Get(context.Background(), args[0])
		if err != nil {
			return fmt.Errorf("get request failed: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		fmt.Printf("ID:        %s\n", resp.ID)
		fmt.Printf("Status:    %s\n", resp.Status)
		fmt.Printf("Signer:    %s\n", resp.SignerAddress)
		fmt.Printf("Chain:     %s\n", resp.ChainID)
		fmt.Printf("Type:      %s\n", resp.SignType)
		fmt.Printf("API Key:   %s\n", resp.APIKeyID)
		fmt.Printf("Created:   %s\n", resp.CreatedAt.Format(time.RFC3339))
		if resp.Signature != "" {
			fmt.Printf("Signature: %s\n", resp.Signature)
		}
		if resp.SignedData != "" {
			fmt.Printf("Signed:    %s\n", resp.SignedData)
		}
		if resp.ErrorMessage != "" {
			fmt.Printf("Error:     %s\n", resp.ErrorMessage)
		}
		return nil
	},
}

// ── request approve ─────────────────────────────────────────────────────────

var (
	reqApproveRuleType string
	reqApproveRuleMode string
	reqApproveRuleName string
	reqApproveMaxValue string
)

var requestApproveCmd = &cobra.Command{
	Use:   "approve <request-id>",
	Short: "Approve a pending signing request (requires signer owner API key)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		req := &evm.ApproveRequest{
			Approved: true,
			RuleType: reqApproveRuleType,
			RuleMode: reqApproveRuleMode,
			RuleName: reqApproveRuleName,
			MaxValue: reqApproveMaxValue,
		}

		resp, err := c.EVM.Requests.Approve(context.Background(), args[0], req)
		if err != nil {
			return fmt.Errorf("approve failed: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		fmt.Printf("Request:   %s\n", resp.RequestID)
		fmt.Printf("Status:    %s\n", resp.Status)
		if resp.Signature != "" {
			fmt.Printf("Signature: %s\n", resp.Signature)
		}
		if resp.SignedData != "" {
			fmt.Printf("Signed:    %s\n", resp.SignedData)
		}
		if resp.Message != "" {
			fmt.Printf("Message:   %s\n", resp.Message)
		}
		return nil
	},
}

// ── request reject ──────────────────────────────────────────────────────────

var requestRejectCmd = &cobra.Command{
	Use:   "reject <request-id>",
	Short: "Reject a pending signing request (requires signer owner API key)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		req := &evm.ApproveRequest{
			Approved: false,
		}

		resp, err := c.EVM.Requests.Approve(context.Background(), args[0], req)
		if err != nil {
			return fmt.Errorf("reject failed: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(resp)
		}

		fmt.Printf("Request:   %s\n", resp.RequestID)
		fmt.Printf("Status:    %s\n", resp.Status)
		if resp.Message != "" {
			fmt.Printf("Message:   %s\n", resp.Message)
		}
		return nil
	},
}

// ── request preview-rule ────────────────────────────────────────────────────

var (
	reqPreviewRuleType string
	reqPreviewRuleMode string
	reqPreviewRuleName string
	reqPreviewMaxValue string
)

var requestPreviewRuleCmd = &cobra.Command{
	Use:   "preview-rule <request-id>",
	Short: "Preview what rule would be generated for a request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		req := &evm.PreviewRuleRequest{
			RuleType: reqPreviewRuleType,
			RuleMode: reqPreviewRuleMode,
			RuleName: reqPreviewRuleName,
			MaxValue: reqPreviewMaxValue,
		}

		resp, err := c.EVM.Requests.PreviewRule(context.Background(), args[0], req)
		if err != nil {
			return fmt.Errorf("preview rule failed: %w", err)
		}

		return printJSON(resp)
	},
}

// ── guard resume ────────────────────────────────────────────────────────────

var guardCmd = &cobra.Command{
	Use:   "guard",
	Short: "Approval guard operations",
}

var guardResumeCmd = &cobra.Command{
	Use:   "resume",
	Short: "Resume the approval guard (unpause signing after guard trip)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		if err := c.EVM.Guard.Resume(context.Background()); err != nil {
			return fmt.Errorf("guard resume failed: %w", err)
		}

		fmt.Println("Approval guard resumed.")
		return nil
	},
}

func init() {
	// request list
	requestListCmd.Flags().StringVar(&reqListStatus, "status", "", "Filter by status (pending, authorizing, signing, completed, rejected, failed)")
	requestListCmd.Flags().StringVar(&reqListSigner, "signer", "", "Filter by signer address")
	requestListCmd.Flags().StringVar(&reqListChainID, "chain-id", "", "Filter by chain ID")
	requestListCmd.Flags().IntVar(&reqListLimit, "limit", 20, "Max results")

	// request approve
	requestApproveCmd.Flags().StringVar(&reqApproveRuleType, "rule-type", "", "Auto-generate rule on approval (evm_address_list, evm_contract_method, evm_value_limit)")
	requestApproveCmd.Flags().StringVar(&reqApproveRuleMode, "rule-mode", "", "Rule mode (whitelist, blocklist)")
	requestApproveCmd.Flags().StringVar(&reqApproveRuleName, "rule-name", "", "Custom rule name")
	requestApproveCmd.Flags().StringVar(&reqApproveMaxValue, "max-value", "", "Max value for evm_value_limit rule")

	// request preview-rule
	requestPreviewRuleCmd.Flags().StringVar(&reqPreviewRuleType, "rule-type", "", "Rule type to preview (required)")
	requestPreviewRuleCmd.Flags().StringVar(&reqPreviewRuleMode, "rule-mode", "", "Rule mode (required)")
	requestPreviewRuleCmd.Flags().StringVar(&reqPreviewRuleName, "rule-name", "", "Custom rule name")
	requestPreviewRuleCmd.Flags().StringVar(&reqPreviewMaxValue, "max-value", "", "Max value for evm_value_limit")

	requestCmd.AddCommand(requestListCmd)
	requestCmd.AddCommand(requestGetCmd)
	requestCmd.AddCommand(requestApproveCmd)
	requestCmd.AddCommand(requestRejectCmd)
	requestCmd.AddCommand(requestPreviewRuleCmd)

	guardCmd.AddCommand(guardResumeCmd)
}
