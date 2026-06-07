package admin

import (
	"fmt"

	"github.com/spf13/cobra"
)

var budgetCmd = &cobra.Command{
	Use:   "budget",
	Short: "Manage rule and simulation budgets",
}

var budgetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all budgets",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		resp, err := c.EVM.Budgets.List(cmd.Context(), nil)
		if err != nil {
			return fmt.Errorf("list budgets: %w", err)
		}
		return printJSON(resp)
	},
}

var budgetDeleteCmd = &cobra.Command{
	Use:   "delete <budget-id>",
	Short: "Delete a budget by its primary key (64-char hash from budget list)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Budgets.Delete(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("delete budget: %w", err)
		}
		fmt.Printf("Budget %s deleted\n", args[0])
		return nil
	},
}

var budgetDeleteByRuleCmd = &cobra.Command{
	Use:   "delete-by-rule <rule-id>",
	Short: "Delete all budget rows for a rule_id (cleans up orphaned budgets after rule deletion)",
	Long: `Deletes every budget row whose rule_id matches, including orphaned rows left behind when a rule was removed without atomic budget cleanup.

Use the rule_id from "budget list" (e.g. inst_abc123...), NOT the rule name. Do not use "evm rule delete" for orphan cleanup — that endpoint only deletes rules.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.EVM.Budgets.DeleteByRuleID(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("delete budgets by rule: %w", err)
		}
		fmt.Printf("Budgets for rule %s deleted\n", args[0])
		return nil
	},
}

func init() {
	budgetCmd.AddCommand(budgetListCmd)
	budgetCmd.AddCommand(budgetDeleteCmd)
	budgetCmd.AddCommand(budgetDeleteByRuleCmd)
	evmCmd.AddCommand(budgetCmd)
}
