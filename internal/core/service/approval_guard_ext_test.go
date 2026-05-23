package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/notify"
)

// ---------------------------------------------------------------------------
// TestSendPauseAlert - actual send path with mock notify
// ---------------------------------------------------------------------------

func TestSendPauseAlert_WithNotifyService(t *testing.T) {
	logger := newTestLogger()

	t.Run("send_alert_with_notify_service", func(t *testing.T) {
		svc, err := notify.NewNotifyService(&notify.Config{})
		require.NoError(t, err)
		svc.Start(context.Background())
		defer svc.Stop()

		ch := &notify.Channel{}

		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			NotifySvc:             svc,
			Channel:               ch,
			Logger:                logger,
		})
		require.NoError(t, err)

		// Trigger the guard with a rejection; this should call sendPauseAlert.
		guard.RecordManualApproval()
		assert.True(t, guard.IsPaused())
	})

	t.Run("send_alert_with_nil_channel_logs_warning", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			NotifySvc:             nil,
			Channel:               &notify.Channel{},
			Logger:                logger,
		})
		require.NoError(t, err)
		// Should not panic - sendPauseAlert will warn but not fail
		guard.RecordManualApproval()
		assert.True(t, guard.IsPaused())
	})

	t.Run("send_alert_resume_hint_includes_auto_resume", func(t *testing.T) {
		svc, err := notify.NewNotifyService(&notify.Config{})
		require.NoError(t, err)
		svc.Start(context.Background())
		defer svc.Stop()

		ch := &notify.Channel{}

		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			ResumeAfter:           2 * time.Hour,
			NotifySvc:             svc,
			Channel:               ch,
			Logger:                logger,
		})
		require.NoError(t, err)

		guard.RecordManualApproval()
		assert.True(t, guard.IsPaused())
	})

	t.Run("send_alert_without_auto_resume", func(t *testing.T) {
		svc, err := notify.NewNotifyService(&notify.Config{})
		require.NoError(t, err)
		svc.Start(context.Background())
		defer svc.Stop()

		ch := &notify.Channel{}

		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			ResumeAfter:           0, // no auto-resume
			NotifySvc:             svc,
			Channel:               ch,
			Logger:                logger,
		})
		require.NoError(t, err)

		guard.RecordManualApproval()
		assert.True(t, guard.IsPaused())
	})
}

// ---------------------------------------------------------------------------
// TestRecordNonManualApproval_DoesNotTriggerPause
// ---------------------------------------------------------------------------

func TestRecordNonManualApproval_DoesNotTriggerPause(t *testing.T) {
	logger := newTestLogger()
	guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
		Window:                5 * time.Minute,
		RejectionThresholdPct: 50,
		MinSamples:            3,
		Logger:                logger,
	})
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		guard.RecordNonManualApproval()
	}
	assert.False(t, guard.IsPaused(), "non-manual approvals alone should not trigger pause")
}

// ---------------------------------------------------------------------------
// TestRecordRuleRejected_TriggersPause
// ---------------------------------------------------------------------------

func TestRecordRuleRejected_TriggersPause(t *testing.T) {
	logger := newTestLogger()
	guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
		Window:                5 * time.Minute,
		RejectionThresholdPct: 50,
		MinSamples:            3,
		Logger:                logger,
	})
	require.NoError(t, err)

	guard.RecordRuleRejected()
	guard.RecordRuleRejected()
	assert.False(t, guard.IsPaused())

	guard.RecordRuleRejected()
	assert.True(t, guard.IsPaused())
}

// ---------------------------------------------------------------------------
// TestResumeSafety
// ---------------------------------------------------------------------------

func TestResumeSafety(t *testing.T) {
	logger := newTestLogger()
	guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
		Window:                5 * time.Minute,
		RejectionThresholdPct: 1,
		MinSamples:            1,
		Logger:                logger,
	})
	require.NoError(t, err)

	// Resume on unpaused guard should not panic
	guard.Resume()
	assert.False(t, guard.IsPaused())

	// Double resume is safe
	guard.Resume()
	assert.False(t, guard.IsPaused())
}

// ---------------------------------------------------------------------------
// TestPauseResumePauseAgain
// ---------------------------------------------------------------------------

func TestPauseResumePauseAgain(t *testing.T) {
	logger := newTestLogger()
	guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
		Window:                5 * time.Minute,
		RejectionThresholdPct: 1,
		MinSamples:            1,
		ResumeAfter:           2 * time.Hour,
		Logger:                logger,
	})
	require.NoError(t, err)

	// Pause
	guard.RecordManualApproval()
	assert.True(t, guard.IsPaused())

	// Resume
	guard.Resume()
	assert.False(t, guard.IsPaused())

	// Pause again
	guard.RecordManualApproval()
	assert.True(t, guard.IsPaused())

	// Resume again
	guard.Resume()
	assert.False(t, guard.IsPaused())
}
