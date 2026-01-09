package service

import (
	"context"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/notify"
)

// NotifyServiceNotifier implements Notifier using NotifyService
type NotifyServiceNotifier struct {
	notifyService *notify.NotifyService
	channels      *notify.Channel
	priority      int
	sound         string
}

// NotifyServiceNotifierConfig configuration for NotifyServiceNotifier
type NotifyServiceNotifierConfig struct {
	NotifyService *notify.NotifyService
	Channels      *notify.Channel
	Priority      int    // Pushover priority (default: 1 for high)
	Sound         string // Pushover sound (default: "persistent")
}

// NewNotifyServiceNotifier creates a new NotifyServiceNotifier
func NewNotifyServiceNotifier(cfg NotifyServiceNotifierConfig) (*NotifyServiceNotifier, error) {
	if cfg.NotifyService == nil {
		return nil, fmt.Errorf("notify service is required")
	}
	if cfg.Channels == nil {
		return nil, fmt.Errorf("channels are required")
	}

	priority := cfg.Priority
	if priority == 0 {
		priority = 1 // High priority by default
	}

	sound := cfg.Sound
	if sound == "" {
		sound = "persistent"
	}

	return &NotifyServiceNotifier{
		notifyService: cfg.NotifyService,
		channels:      cfg.Channels,
		priority:      priority,
		sound:         sound,
	}, nil
}

// SendApprovalRequest sends an approval notification
func (n *NotifyServiceNotifier) SendApprovalRequest(ctx context.Context, req *types.SignRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}

	msg := formatApprovalMessage(req)

	if err := n.notifyService.SendWithPriority(n.channels, msg, n.priority, n.sound); err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	return nil
}

// formatApprovalMessage formats the approval request message
func formatApprovalMessage(req *types.SignRequest) string {
	return fmt.Sprintf(
		"[Remote Signer] Approval Required\n\n"+
			"Request ID: %s\n"+
			"Chain: %s (ID: %s)\n"+
			"Signer: %s\n"+
			"Sign Type: %s\n"+
			"Status: %s\n\n"+
			"Please review and approve or reject this request.",
		req.ID,
		req.ChainType,
		req.ChainID,
		req.SignerAddress,
		req.SignType,
		req.Status,
	)
}

// Compile-time check
var _ Notifier = (*NotifyServiceNotifier)(nil)
