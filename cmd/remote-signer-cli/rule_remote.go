package main

import (
	"encoding/json"
	"fmt"
	"os"
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
		[]string{"ID", "NAME", "TYPE", "MODE", "ENABLED", "STATUS"},
		func() [][]string {
			rows := make([][]string, len(resp.Rules))
			for i, r := range resp.Rules {
				rows[i] = []string{r.ID, r.Name, r.Type, r.Mode, strconv.FormatBool(r.Enabled), r.Status}
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

	data, err := os.ReadFile(flagRuleCreateFile)
	if err != nil {
		return fmt.Errorf("read file %s: %w", flagRuleCreateFile, err)
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
	w.Flush()
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
	ruleCreateCmd.MarkFlagRequired("file")

	// toggle flags
	ruleToggleCmd.Flags().BoolVar(&flagToggleEnable, "enable", false, "Enable the rule")
	ruleToggleCmd.Flags().BoolVar(&flagToggleDisable, "disable", false, "Disable the rule")

	// reject flags
	ruleRejectCmd.Flags().StringVar(&flagRejectReason, "reason", "", "Reason for rejection")
	ruleRejectCmd.MarkFlagRequired("reason")

	// register all subcommands
	ruleCmd.AddCommand(ruleListRemoteCmd)
	ruleCmd.AddCommand(ruleGetCmd)
	ruleCmd.AddCommand(ruleCreateCmd)
	ruleCmd.AddCommand(ruleDeleteCmd)
	ruleCmd.AddCommand(ruleToggleCmd)
	ruleCmd.AddCommand(ruleApproveCmd)
	ruleCmd.AddCommand(ruleRejectCmd)
	ruleCmd.AddCommand(ruleBudgetsCmd)
}
