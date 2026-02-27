package service

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestNewManualApprovalGuard
// ---------------------------------------------------------------------------

func TestNewManualApprovalGuard(t *testing.T) {
	logger := newTestLogger()

	t.Run("valid_config", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 3,
			Logger:    logger,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if guard == nil {
			t.Fatal("expected non-nil guard")
		}
	})

	t.Run("zero_threshold_error", func(t *testing.T) {
		_, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 0,
			Logger:    logger,
		})
		if err == nil {
			t.Fatal("expected error for zero threshold")
		}
		if !strings.Contains(err.Error(), "threshold must be positive") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("negative_threshold_error", func(t *testing.T) {
		_, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: -1,
			Logger:    logger,
		})
		if err == nil {
			t.Fatal("expected error for negative threshold")
		}
	})

	t.Run("nil_logger_error", func(t *testing.T) {
		_, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 3,
			Logger:    nil,
		})
		if err == nil {
			t.Fatal("expected error for nil logger")
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestIsPaused
// ---------------------------------------------------------------------------

func TestIsPaused(t *testing.T) {
	t.Run("initially_not_paused", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 3,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}
		if guard.IsPaused() {
			t.Error("expected guard to not be paused initially")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRecordManualApproval
// ---------------------------------------------------------------------------

func TestRecordManualApproval(t *testing.T) {
	t.Run("pauses_after_threshold", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 3,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		// Record under threshold
		guard.RecordManualApproval()
		guard.RecordManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused before reaching threshold")
		}

		// Hit threshold
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected guard to be paused after reaching threshold")
		}
	})

	t.Run("threshold_1_pauses_immediately", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    time.Minute,
			Threshold: 1,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected guard to be paused after one rejection with threshold 1")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRecordRuleRejected
// ---------------------------------------------------------------------------

func TestRecordRuleRejected(t *testing.T) {
	t.Run("counts_toward_threshold", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 2,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordRuleRejected()
		if guard.IsPaused() {
			t.Error("should not be paused after one rejection")
		}

		guard.RecordRuleRejected()
		if !guard.IsPaused() {
			t.Error("expected paused after reaching threshold with rule rejections")
		}
	})

	t.Run("mixed_manual_and_rule_rejections", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 3,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordManualApproval()
		guard.RecordRuleRejected()
		if guard.IsPaused() {
			t.Error("should not be paused yet")
		}
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused after mixed rejections reaching threshold")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRecordNonManualApproval
// ---------------------------------------------------------------------------

func TestRecordNonManualApproval(t *testing.T) {
	t.Run("resets_consecutive_counter", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 3,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		// Record 2 rejections (below threshold)
		guard.RecordManualApproval()
		guard.RecordManualApproval()

		// Reset with a non-manual approval
		guard.RecordNonManualApproval()

		// Record 2 more (still below threshold due to reset)
		guard.RecordManualApproval()
		guard.RecordManualApproval()

		if guard.IsPaused() {
			t.Error("should not be paused because counter was reset")
		}

		// One more pushes it over
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused after reaching threshold post-reset")
		}
	})
}

// ---------------------------------------------------------------------------
// TestResume
// ---------------------------------------------------------------------------

func TestResume(t *testing.T) {
	t.Run("resumes_after_pause", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 1,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Fatal("expected guard to be paused")
		}

		guard.Resume()
		if guard.IsPaused() {
			t.Error("expected guard to not be paused after resume")
		}
	})

	t.Run("resume_clears_consecutive_counter", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 2,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		// Trigger pause
		guard.RecordManualApproval()
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Fatal("expected guard to be paused")
		}

		// Resume
		guard.Resume()

		// Recording one more should not trigger pause
		guard.RecordManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused after resume + single rejection (threshold=2)")
		}
	})
}

// ---------------------------------------------------------------------------
// TestAutoResume
// ---------------------------------------------------------------------------

func TestAutoResume(t *testing.T) {
	t.Run("auto_resumes_after_duration", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:      5 * time.Minute,
			Threshold:   1,
			ResumeAfter: 100 * time.Millisecond,
			Logger:      newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Fatal("expected paused")
		}

		// Wait for auto-resume
		time.Sleep(200 * time.Millisecond)
		if guard.IsPaused() {
			t.Error("expected auto-resume after duration")
		}
	})

	t.Run("no_auto_resume_when_zero_duration", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:      5 * time.Minute,
			Threshold:   1,
			ResumeAfter: 0, // no auto-resume
			Logger:      newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Fatal("expected paused")
		}

		time.Sleep(50 * time.Millisecond)
		if !guard.IsPaused() {
			t.Error("should remain paused without auto-resume configured")
		}

		// Must manually resume
		guard.Resume()
		if guard.IsPaused() {
			t.Error("should be unpaused after manual resume")
		}
	})
}

// ---------------------------------------------------------------------------
// TestWindowExpiry
// ---------------------------------------------------------------------------

func TestWindowExpiry(t *testing.T) {
	t.Run("rejections_outside_window_do_not_trigger_pause", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    100 * time.Millisecond,
			Threshold: 3,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordManualApproval()
		guard.RecordManualApproval()

		// Wait for window to expire
		time.Sleep(150 * time.Millisecond)

		// This third rejection should not trigger pause because the first two are outside the window
		guard.RecordManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused because earlier rejections are outside the window")
		}
	})

	t.Run("zero_window_means_no_window_check", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    0, // no window = always counts
			Threshold: 2,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordManualApproval()
		time.Sleep(10 * time.Millisecond)
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused with zero window (no expiry)")
		}
	})
}

// ---------------------------------------------------------------------------
// TestSendPauseAlert
// ---------------------------------------------------------------------------

func TestSendPauseAlert(t *testing.T) {
	t.Run("no_panic_without_notify_service", func(t *testing.T) {
		// Guard without notify service should not panic
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 1,
			Logger:    newTestLogger(),
			// NotifySvc and Channel are nil
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		// This triggers sendPauseAlert internally
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused")
		}
		// If we got here without panic, the test passes
	})
}

// ---------------------------------------------------------------------------
// TestResumeWithActiveTimer
// ---------------------------------------------------------------------------

func TestResumeWithActiveTimer(t *testing.T) {
	t.Run("resume_stops_active_timer", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:      5 * time.Minute,
			Threshold:   1,
			ResumeAfter: 10 * time.Second, // long timer
			Logger:      newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Fatal("expected paused")
		}

		// Manually resume while timer is active
		guard.Resume()
		if guard.IsPaused() {
			t.Error("expected not paused after manual resume")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRepeatedPause
// ---------------------------------------------------------------------------

func TestRepeatedPause(t *testing.T) {
	t.Run("pause_resume_pause_again", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:      5 * time.Minute,
			Threshold:   1,
			ResumeAfter: 100 * time.Millisecond,
			Logger:      newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}

		// First pause
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Fatal("expected paused")
		}

		// Resume
		guard.Resume()
		if guard.IsPaused() {
			t.Fatal("expected not paused after resume")
		}

		// Second pause
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused again after second rejection")
		}

		// Wait for auto-resume
		time.Sleep(200 * time.Millisecond)
		if guard.IsPaused() {
			t.Error("expected auto-resume after duration")
		}
	})
}
