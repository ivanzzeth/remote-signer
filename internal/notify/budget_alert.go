package notify

import (
	"context"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// BudgetAlertNotifier sends budget threshold alerts via the NotifyService.
// It implements rule.BudgetAlertNotifier to avoid circular package dependencies.
type BudgetAlertNotifier struct {
	notifyService *NotifyService
	channels      *Channel
	priority      int
	sound         string
}

// NewBudgetAlertNotifier creates a new budget alert notifier.
func NewBudgetAlertNotifier(notifyService *NotifyService, channels *Channel) *BudgetAlertNotifier {
	return &BudgetAlertNotifier{
		notifyService: notifyService,
		channels:      channels,
		priority:      1, // High priority
		sound:         "persistent",
	}
}

// SendBudgetAlert sends a budget threshold alert notification.
func (n *BudgetAlertNotifier) SendBudgetAlert(
	ctx context.Context,
	ruleID types.RuleID,
	unit string,
	spent string,
	maxTotal string,
	pct int64,
	alertPct int,
) error {
	if n.notifyService == nil || n.channels == nil {
		return nil
	}

	msg := fmt.Sprintf(
		"⚠️ [Remote Signer] Budget Alert\n\n"+
			"Rule ID: %s\n"+
			"Unit: %s\n"+
			"Spent: %s / %s (%d%%)\n"+
			"Alert Threshold: %d%%\n\n"+
			"Budget usage has reached the alert threshold. "+
			"Please review and consider increasing the budget or pausing the rule.",
		ruleID, unit, spent, maxTotal, pct, alertPct,
	)

	if err := n.notifyService.SendWithPriority(n.channels, msg, n.priority, n.sound); err != nil {
		return fmt.Errorf("failed to send budget alert: %w", err)
	}

	return nil
}
