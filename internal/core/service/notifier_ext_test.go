package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/notify"
)

// ---------------------------------------------------------------------------
// TestNewNotifyServiceNotifier
// ---------------------------------------------------------------------------

func TestNewNotifyServiceNotifier_Valid(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	ch := &notify.Channel{
		Slack: []string{"#test"},
	}
	n, err := NewNotifyServiceNotifier(NotifyServiceNotifierConfig{
		NotifyService: svc,
		Channels:      ch,
	})
	require.NoError(t, err)
	require.NotNil(t, n)
}

func TestNewNotifyServiceNotifier_NilChannels(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	_, err = NewNotifyServiceNotifier(NotifyServiceNotifierConfig{
		NotifyService: svc,
		Channels:      nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channels are required")
}

func TestNewNotifyServiceNotifier_DefaultPriorityAndSound(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	n, err := NewNotifyServiceNotifier(NotifyServiceNotifierConfig{
		NotifyService: svc,
		Channels:      &notify.Channel{},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, n.priority)
	assert.Equal(t, "persistent", n.sound)
}

func TestNewNotifyServiceNotifier_ExplicitPriorityAndSound(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	n, err := NewNotifyServiceNotifier(NotifyServiceNotifierConfig{
		NotifyService: svc,
		Channels:      &notify.Channel{},
		Priority:      2,
		Sound:         "incoming",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, n.priority)
	assert.Equal(t, "incoming", n.sound)
}

// ---------------------------------------------------------------------------
// TestSendApprovalRequest
// ---------------------------------------------------------------------------

func TestSendApprovalRequest_ValidRequest(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)
	// Start the service so the channel consumer goroutine is running.
	svc.Start(context.Background())
	defer svc.Stop()

	n, err := NewNotifyServiceNotifier(NotifyServiceNotifierConfig{
		NotifyService: svc,
		Channels:      &notify.Channel{},
	})
	require.NoError(t, err)

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xabc",
		SignType:      "eth_signTransaction",
		Status:        types.StatusAuthorizing,
	}
	err = n.SendApprovalRequest(context.Background(), req)
	// No clients are configured so the message is dropped silently.
	require.NoError(t, err)
}

func TestSendApprovalRequest_EmptyChannelDoesNotError(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)
	svc.Start(context.Background())
	defer svc.Stop()

	n, err := NewNotifyServiceNotifier(NotifyServiceNotifierConfig{
		NotifyService: svc,
		Channels:      &notify.Channel{}, // empty channel with no recipients
	})
	require.NoError(t, err)

	req := &types.SignRequest{
		ID:            "req-2",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "137",
		SignerAddress: "0xdef",
		SignType:      "eth_sign",
		Status:        types.StatusCompleted,
	}
	err = n.SendApprovalRequest(context.Background(), req)
	require.NoError(t, err)
}

func TestSendApprovalRequest_NilRequest(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	n, err := NewNotifyServiceNotifier(NotifyServiceNotifierConfig{
		NotifyService: svc,
		Channels:      &notify.Channel{},
	})
	require.NoError(t, err)

	err = n.SendApprovalRequest(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request is required")
}
