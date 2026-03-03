package service

import (
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------------------------------------------------------------------------
// TestNewNotifyServiceNotifier
// ---------------------------------------------------------------------------

func TestNewNotifyServiceNotifier(t *testing.T) {
	t.Run("nil_notify_service", func(t *testing.T) {
		_, err := NewNotifyServiceNotifier(NotifyServiceNotifierConfig{
			NotifyService: nil,
		})
		if err == nil {
			t.Fatal("expected error for nil notify service")
		}
		if !strings.Contains(err.Error(), "notify service is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_channels", func(t *testing.T) {
		// We cannot easily construct a real NotifyService without external deps,
		// but we can test the nil channels case since it's checked before NotifyService is used.
		// Unfortunately NotifyService check comes first, so we can't test nil channels
		// without a real NotifyService.
		// This test verifies the error message for nil channels.
		// We would need the notify service to not be nil, which requires config.
		// Skip this sub-test as it requires a real notify service.
		t.Skip("requires real NotifyService instance")
	})
}

// ---------------------------------------------------------------------------
// TestFormatApprovalMessage
// ---------------------------------------------------------------------------

func TestFormatApprovalMessage(t *testing.T) {
	t.Run("formats_all_fields", func(t *testing.T) {
		req := &types.SignRequest{
			ID:            "req-123",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xabcdef1234567890abcdef1234567890abcdef12",
			SignType:      "eth_signTransaction",
			Status:        types.StatusAuthorizing,
		}

		msg := formatApprovalMessage(req)

		// Verify all fields appear in the message
		expectedParts := []string{
			"Approval Required",
			"req-123",
			string(types.ChainTypeEVM),
			"1",
			"0xabcdef1234567890abcdef1234567890abcdef12",
			"eth_signTransaction",
			string(types.StatusAuthorizing),
			"review and approve or reject",
		}

		for _, part := range expectedParts {
			if !strings.Contains(msg, part) {
				t.Errorf("message should contain %q, got: %s", part, msg)
			}
		}
	})

	t.Run("handles_empty_fields", func(t *testing.T) {
		req := &types.SignRequest{
			ID: "req-empty",
		}

		msg := formatApprovalMessage(req)
		if !strings.Contains(msg, "req-empty") {
			t.Errorf("message should contain request ID: %s", msg)
		}
	})
}

// ---------------------------------------------------------------------------
// TestNotifyServiceNotifierSendApprovalRequest
// ---------------------------------------------------------------------------

func TestNotifyServiceNotifierSendApprovalRequest_NilRequest(t *testing.T) {
	// We cannot easily construct a NotifyServiceNotifier without a real NotifyService,
	// but we can test the nil request guard by constructing the struct directly.
	notifier := &NotifyServiceNotifier{}

	err := notifier.SendApprovalRequest(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	if !strings.Contains(err.Error(), "request is required") {
		t.Errorf("unexpected error: %v", err)
	}
}
