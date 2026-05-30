package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// --- rule list ---

var ruleListRemoteCmd = &cobra.Command{
	Use:   "list",
	Short: "List rules from server",
	RunE:  runRuleListRemote,
}

var (
	flagRuleListType    string
	flagRuleListMode    string
	flagRuleListEnabled string // "true", "false", or "" (unset)
	flagRuleListOwner   string
	flagRuleListLimit   int
	flagRuleListOffset  int
)

func runRuleListRemote(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	filter := &evm.ListRulesFilter{
		Type:   flagRuleListType,
		Mode:   flagRuleListMode,
		Limit:  flagRuleListLimit,
		Offset: flagRuleListOffset,
	}
	if flagRuleListEnabled != "" {
		b, err := strconv.ParseBool(flagRuleListEnabled)
		if err != nil {
			return fmt.Errorf("invalid --enabled value %q: %w", flagRuleListEnabled, err)
		}
		filter.Enabled = &b
	}
	// owner is not in ListRulesFilter; use signer_address as closest match
	if flagRuleListOwner != "" {
		filter.SignerAddress = flagRuleListOwner
	}

	resp, err := c.EVM.Rules.List(cmd.Context(), filter)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	if flagOutputFormat == "json" {
		return printJSON(resp)
	}

	fmt.Printf("Total: %d\n", resp.Total)
	printTable(
		[]string{"PRI", "ID", "NAME", "TYPE", "MODE", "ENABLED", "STATUS"},
		func() [][]string {
			rows := make([][]string, len(resp.Rules))
			for i, r := range resp.Rules {
				rows[i] = []string{strconv.Itoa(r.Priority), r.ID, r.Name, r.Type, r.Mode, strconv.FormatBool(r.Enabled), r.Status}
			}
			return rows
		}(),
	)
	return nil
}

// --- rule get ---

var ruleGetCmd = &cobra.Command{
	Use:   "get <rule-id>",
	Short: "Get rule details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		rule, err := c.EVM.Rules.Get(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("get rule: %w", err)
		}
		return printJSON(rule)
	},
}

// --- rule create ---

var ruleCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create rule from YAML/JSON file",
	RunE:  runRuleCreate,
}

var flagRuleCreateFile string

func runRuleCreate(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	cleanPath := filepath.Clean(flagRuleCreateFile)
	data, err := os.ReadFile(cleanPath) // #nosec G304 -- user-provided CLI flag, path cleaned
	if err != nil {
		return fmt.Errorf("read file %s: %w", cleanPath, err)
	}

	var req evm.CreateRuleRequest
	// Try YAML first (superset of JSON)
	if err := yaml.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("unmarshal rule definition: %w", err)
	}

	rule, err := c.EVM.Rules.Create(cmd.Context(), &req)
	if err != nil {
		return fmt.Errorf("create rule: %w", err)
	}
	return printJSON(rule)
}

// --- rule delete ---

var ruleDeleteCmd = &cobra.Command{
	Use:   "delete <rule-id>",
	Short: "Delete a rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Rules.Delete(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("delete rule: %w", err)
		}
		fmt.Printf("Rule %s deleted\n", args[0])
		return nil
	},
}

// --- rule toggle ---

var ruleToggleCmd = &cobra.Command{
	Use:   "toggle <rule-id>",
	Short: "Enable or disable a rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runRuleToggle,
}

var (
	flagToggleEnable  bool
	flagToggleDisable bool
)

func runRuleToggle(cmd *cobra.Command, args []string) error {
	if flagToggleEnable == flagToggleDisable {
		return fmt.Errorf("exactly one of --enable or --disable is required")
	}

	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	rule, err := c.EVM.Rules.Toggle(cmd.Context(), args[0], flagToggleEnable)
	if err != nil {
		return fmt.Errorf("toggle rule: %w", err)
	}
	return printJSON(rule)
}

// --- rule approve ---

var ruleApproveCmd = &cobra.Command{
	Use:   "approve <rule-id>",
	Short: "Approve a pending rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		rule, err := c.EVM.Rules.Approve(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("approve rule: %w", err)
		}
		return printJSON(rule)
	},
}

// --- rule reject ---

var ruleRejectCmd = &cobra.Command{
	Use:   "reject <rule-id>",
	Short: "Reject a pending rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runRuleReject,
}

var flagRejectReason string

func runRuleReject(cmd *cobra.Command, args []string) error {
	if flagRejectReason == "" {
		return fmt.Errorf("--reason is required")
	}

	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	rule, err := c.EVM.Rules.Reject(cmd.Context(), args[0], flagRejectReason)
	if err != nil {
		return fmt.Errorf("reject rule: %w", err)
	}
	return printJSON(rule)
}

// --- rule budgets ---

var ruleBudgetsCmd = &cobra.Command{
	Use:   "budgets <rule-id>",
	Short: "List rule budgets",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		budgets, err := c.EVM.Rules.ListBudgets(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("list budgets: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(budgets)
		}

		printTable(
			[]string{"ID", "UNIT", "MAX_TOTAL", "MAX_PER_TX", "SPENT", "TX_COUNT", "MAX_TX_COUNT"},
			func() [][]string {
				rows := make([][]string, len(budgets))
				for i, b := range budgets {
					rows[i] = []string{
						b.ID, b.Unit, b.MaxTotal, b.MaxPerTx, b.Spent,
						strconv.Itoa(b.TxCount), strconv.Itoa(b.MaxTxCount),
					}
				}
				return rows
			}(),
		)
		return nil
	},
}

// --- helpers ---

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush table: %v\n", err)
	}
}

// --- rule validate ---

var (
	flagRuleValidateAll bool
)

var ruleValidateCmd = &cobra.Command{
	Use:   "validate [rule-id]",
	Short: "Validate a rule's test cases (evm_js only) or all rules with --all",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		if flagRuleValidateAll {
			resp, err := c.EVM.Rules.BatchValidate(cmd.Context())
			if err != nil {
				return fmt.Errorf("batch validate: %w", err)
			}
			if flagOutputFormat == "json" {
				return printJSON(resp)
			}
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
				for _, tc := range r.Results {
					tcStatus := "✓"
					if !tc.Passed {
						tcStatus = "✗"
					}
					fmt.Printf("    %s %s", tcStatus, tc.Name)
					if tc.Reason != "" {
						fmt.Printf(" (%s)", tc.Reason)
					}
					fmt.Println()
				}
			}
			return nil
		}

		if len(args) == 0 {
			return fmt.Errorf("rule-id is required (or use --all for batch)")
		}

		resp, err := c.EVM.Rules.Validate(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("validate rule: %w", err)
		}
		if flagOutputFormat == "json" {
			return printJSON(resp)
		}
		status := "PASS"
		if !resp.Valid {
			status = "FAIL"
		}
		fmt.Printf("Rule: %s [%s] %s\n", resp.RuleID, status, resp.RuleName)
		if resp.Error != "" {
			fmt.Printf("Error: %s\n", resp.Error)
		}
		for _, tc := range resp.Results {
			tcStatus := "✓"
			if !tc.Passed {
				tcStatus = "✗"
			}
			fmt.Printf("  %s %s", tcStatus, tc.Name)
			if tc.Reason != "" {
				fmt.Printf(" (%s)", tc.Reason)
			}
			fmt.Println()
		}
		return nil
	},
}

// --- registration ---

func init() {
	// list flags
	ruleListRemoteCmd.Flags().StringVar(&flagRuleListType, "type", "", "Filter by rule type")
	ruleListRemoteCmd.Flags().StringVar(&flagRuleListMode, "mode", "", "Filter by rule mode")
	ruleListRemoteCmd.Flags().StringVar(&flagRuleListEnabled, "enabled", "", "Filter by enabled (true/false)")
	ruleListRemoteCmd.Flags().StringVar(&flagRuleListOwner, "owner", "", "Filter by owner/signer address")
	ruleListRemoteCmd.Flags().IntVar(&flagRuleListLimit, "limit", 50, "Max results to return")
	ruleListRemoteCmd.Flags().IntVar(&flagRuleListOffset, "offset", 0, "Offset for pagination")

	// create flags
	ruleCreateCmd.Flags().StringVarP(&flagRuleCreateFile, "file", "f", "", "Path to YAML/JSON rule definition file")
	if err := ruleCreateCmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	// toggle flags
	ruleToggleCmd.Flags().BoolVar(&flagToggleEnable, "enable", false, "Enable the rule")
	ruleToggleCmd.Flags().BoolVar(&flagToggleDisable, "disable", false, "Disable the rule")

	// reject flags
	ruleRejectCmd.Flags().StringVar(&flagRejectReason, "reason", "", "Reason for rejection")
	if err := ruleRejectCmd.MarkFlagRequired("reason"); err != nil {
		panic(err)
	}

	// update flags
	ruleUpdateCmd.Flags().StringVar(&flagUpdateName, "name", "", "New rule name")
	ruleUpdateCmd.Flags().StringVar(&flagUpdateDescription, "description", "", "New description")
	ruleUpdateCmd.Flags().StringArrayVar(&flagUpdateConfig, "set-config", nil, "Set config field (key=value, repeatable)")
	ruleUpdateCmd.Flags().IntVar(&flagUpdatePriority, "priority", 0, "Rule priority (lower = higher, 1 is highest)")

	ruleValidateCmd.Flags().BoolVar(&flagRuleValidateAll, "all", false, "Validate all evm_js rules (batch mode)")

	// register all subcommands
	ruleCmd.AddCommand(ruleListRemoteCmd)
	ruleCmd.AddCommand(ruleGetCmd)
	ruleCmd.AddCommand(ruleCreateCmd)
	ruleCmd.AddCommand(ruleUpdateCmd)
	ruleCmd.AddCommand(ruleDeleteCmd)
	ruleCmd.AddCommand(ruleToggleCmd)
	ruleCmd.AddCommand(ruleApproveCmd)
	ruleCmd.AddCommand(ruleRejectCmd)
	ruleCmd.AddCommand(ruleBudgetsCmd)
	ruleCmd.AddCommand(ruleValidateCmd)
}

// --- rule update ---

var (
	flagUpdateName        string
	flagUpdateDescription string
	flagUpdateConfig      []string
	flagUpdatePriority    int
	flagCreatePriority    int
)

var ruleUpdateCmd = &cobra.Command{
	Use:   "update <rule-id>",
	Short: "Update a rule's config, name, or description",
	Long: `Update a rule. Use --set-config to modify config fields.

Example:
  rule update agent-sign-evm --set-config "allowed_spenders=0xabc,0xdef"
  rule update my-rule --name "New Name" --description "Updated"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}

		req := &evm.UpdateRuleRequest{}

		if flagUpdateName != "" {
			req.Name = flagUpdateName
		}
		if flagUpdateDescription != "" {
			req.Description = flagUpdateDescription
		}

		if len(flagUpdateConfig) > 0 {
			req.Config = make(map[string]interface{})
			for _, kv := range flagUpdateConfig {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid --set-config format %q, expected key=value", kv)
				}
				req.Config[parts[0]] = parts[1]
			}
		}

		rule, err := c.EVM.Rules.Update(cmd.Context(), args[0], req)
		if err != nil {
			return fmt.Errorf("update rule: %w", err)
		}

		if flagOutputFormat == "json" {
			return printJSON(rule)
		}

		fmt.Printf("Rule %s updated\n", rule.ID)
		return nil
	},
}
