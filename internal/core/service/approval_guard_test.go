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

	t.Run("valid_config_with_defaults", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Logger: logger,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if guard == nil {
			t.Fatal("expected non-nil guard")
		}
		// Verify defaults applied
		if guard.window != defaultWindow {
			t.Errorf("expected default window %v, got %v", defaultWindow, guard.window)
		}
		if guard.rejectionThreshPct != defaultRejectionThreshPct {
			t.Errorf("expected default threshold %.0f, got %.0f", defaultRejectionThreshPct, guard.rejectionThreshPct)
		}
		if guard.minSamples != defaultMinSamples {
			t.Errorf("expected default min samples %d, got %d", defaultMinSamples, guard.minSamples)
		}
	})

	t.Run("valid_config_explicit_values", func(t *testing.T) {
		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 30,
			MinSamples:            5,
			Logger:                logger,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if guard.window != 5*time.Minute {
			t.Errorf("expected window 5m, got %v", guard.window)
		}
		if guard.rejectionThreshPct != 30 {
			t.Errorf("expected threshold 30, got %.0f", guard.rejectionThreshPct)
		}
		if guard.minSamples != 5 {
			t.Errorf("expected min samples 5, got %d", guard.minSamples)
		}
	})

	t.Run("threshold_over_100_error", func(t *testing.T) {
		_, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			RejectionThresholdPct: 101,
			Logger:                logger,
		})
		if err == nil {
			t.Fatal("expected error for threshold > 100")
		}
		if !strings.Contains(err.Error(), "rejection threshold percentage must be <= 100") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_logger_error", func(t *testing.T) {
		_, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Logger: nil,
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
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            3,
			Logger:                newTestLogger(),
		})
		if guard.IsPaused() {
			t.Error("expected guard to not be paused initially")
		}
	})
}

// ---------------------------------------------------------------------------
// TestSlidingWindowRateBasedTrigger
// ---------------------------------------------------------------------------

func TestSlidingWindowRateBasedTrigger(t *testing.T) {
	t.Run("triggers_when_rate_exceeds_threshold", func(t *testing.T) {
		// 50% threshold, min 4 samples
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            4,
			Logger:                newTestLogger(),
		})

		// 3 rejections, 1 approval = 75% rejection rate, but only 4 samples
		guard.RecordRuleRejected()
		guard.RecordRuleRejected()
		guard.RecordNonManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused before min samples met")
		}

		// 4th event: rejection -> 3/4 = 75% > 50%, min samples met
		guard.RecordRuleRejected()
		if !guard.IsPaused() {
			t.Error("expected paused after rejection rate exceeded threshold with min samples met")
		}
	})

	t.Run("does_not_trigger_below_threshold", func(t *testing.T) {
		// 50% threshold, min 4 samples
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            4,
			Logger:                newTestLogger(),
		})

		// 2 rejections + 2 approvals = 50% rate, NOT exceeding >50%
		guard.RecordRuleRejected()
		guard.RecordNonManualApproval()
		guard.RecordRuleRejected()
		guard.RecordNonManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused when rate equals threshold (need to exceed)")
		}
	})

	t.Run("alternating_pattern_triggers", func(t *testing.T) {
		// This is the key security test: alternating legit/malicious should trigger
		// when the overall rate exceeds threshold
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 40,
			MinSamples:            6,
			Logger:                newTestLogger(),
		})

		// Alternate: reject, approve, reject, approve, reject, approve
		// = 3/6 = 50% > 40%
		guard.RecordRuleRejected()
		guard.RecordNonManualApproval()
		guard.RecordRuleRejected()
		guard.RecordNonManualApproval()
		guard.RecordRuleRejected()
		if guard.IsPaused() {
			t.Error("should not be paused before min samples met (only 5)")
		}

		guard.RecordNonManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused: alternating pattern has 50% rejection rate which exceeds 40% threshold")
		}
	})

	t.Run("purely_legitimate_does_not_trigger", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            4,
			Logger:                newTestLogger(),
		})

		for i := 0; i < 20; i++ {
			guard.RecordNonManualApproval()
		}
		if guard.IsPaused() {
			t.Error("should not be paused with purely legitimate traffic")
		}
	})
}

// ---------------------------------------------------------------------------
// TestMinSamplesRequirement
// ---------------------------------------------------------------------------

func TestMinSamplesRequirement(t *testing.T) {
	t.Run("all_rejections_below_min_samples_no_trigger", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            10,
			Logger:                newTestLogger(),
		})

		// 9 rejections = 100% rate but below min samples
		for i := 0; i < 9; i++ {
			guard.RecordRuleRejected()
		}
		if guard.IsPaused() {
			t.Error("should not be paused below min samples even with 100% rejection rate")
		}

		// 10th rejection hits min samples, 100% > 50%
		guard.RecordRuleRejected()
		if !guard.IsPaused() {
			t.Error("expected paused after min samples met with 100% rejection rate")
		}
	})

	t.Run("min_samples_1_triggers_on_first_rejection", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			Logger:                newTestLogger(),
		})

		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused after first rejection with min_samples=1")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRecordManualApproval
// ---------------------------------------------------------------------------

func TestRecordManualApproval(t *testing.T) {
	t.Run("counts_as_rejection", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            3,
			Logger:                newTestLogger(),
		})

		// 3 manual approvals = 100% rejection rate
		guard.RecordManualApproval()
		guard.RecordManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused before min samples")
		}
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused after 3 manual approvals (100% rejection rate)")
		}
	})
}

// ---------------------------------------------------------------------------
// TestRecordRuleRejected
// ---------------------------------------------------------------------------

func TestRecordRuleRejected(t *testing.T) {
	t.Run("counts_toward_rejection_rate", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            2,
			Logger:                newTestLogger(),
		})

		guard.RecordRuleRejected()
		if guard.IsPaused() {
			t.Error("should not be paused after one rejection")
		}

		guard.RecordRuleRejected()
		if !guard.IsPaused() {
			t.Error("expected paused after 2 rejections (100% rate)")
		}
	})

	t.Run("mixed_manual_and_rule_rejections", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            3,
			Logger:                newTestLogger(),
		})

		guard.RecordManualApproval()
		guard.RecordRuleRejected()
		if guard.IsPaused() {
			t.Error("should not be paused yet (only 2 samples)")
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
	t.Run("counts_as_approval_in_window", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            6,
			Logger:                newTestLogger(),
		})

		// 2 rejections, then 1 approval, then 2 more rejections, then 1 approval
		// = 4 rejections / 6 total = 66.7% > 50% -- should trigger
		guard.RecordManualApproval()
		guard.RecordManualApproval()
		guard.RecordNonManualApproval()
		guard.RecordManualApproval()
		guard.RecordManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused yet (only 5 samples)")
		}
		guard.RecordNonManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused: 4/6 = 66.7% rejection rate > 50%")
		}
	})

	t.Run("enough_approvals_prevents_trigger", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            4,
			Logger:                newTestLogger(),
		})

		// 1 rejection + 3 approvals = 25% rate, below 50%
		guard.RecordManualApproval()
		guard.RecordNonManualApproval()
		guard.RecordNonManualApproval()
		guard.RecordNonManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused with low rejection rate")
		}
	})
}

// ---------------------------------------------------------------------------
// TestResume
// ---------------------------------------------------------------------------

func TestResume(t *testing.T) {
	t.Run("resumes_after_pause", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			Logger:                newTestLogger(),
		})

		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Fatal("expected guard to be paused")
		}

		guard.Resume()
		if guard.IsPaused() {
			t.Error("expected guard to not be paused after resume")
		}
	})

	t.Run("resume_clears_events", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 50,
			MinSamples:            2,
			Logger:                newTestLogger(),
		})

		// Trigger pause
		guard.RecordManualApproval()
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Fatal("expected guard to be paused")
		}

		// Resume
		guard.Resume()

		// Recording one more should not trigger (events were cleared)
		guard.RecordManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused after resume + single rejection (min samples=2)")
		}
	})
}

// ---------------------------------------------------------------------------
// TestAutoResume
// ---------------------------------------------------------------------------

func TestAutoResume(t *testing.T) {
	t.Run("auto_resumes_after_duration", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			ResumeAfter:           100 * time.Millisecond,
			Logger:                newTestLogger(),
		})

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
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			ResumeAfter:           0, // no auto-resume
			Logger:                newTestLogger(),
		})

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
	t.Run("events_outside_window_are_expired", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                100 * time.Millisecond,
			RejectionThresholdPct: 50,
			MinSamples:            3,
			Logger:                newTestLogger(),
		})

		// Record 2 rejections
		guard.RecordManualApproval()
		guard.RecordManualApproval()

		// Wait for window to expire
		time.Sleep(150 * time.Millisecond)

		// This third rejection should not trigger pause because the first two are outside the window
		// Now we only have 1 event in the window, below min samples
		guard.RecordManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused because earlier events are outside the window")
		}
	})

	t.Run("events_expire_using_nowFunc", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                time.Hour,
			RejectionThresholdPct: 50,
			MinSamples:            4,
			Logger:                newTestLogger(),
		})

		now := time.Now()

		// Record 3 rejections at t=0
		guard.nowFunc = func() time.Time { return now }
		guard.RecordManualApproval()
		guard.RecordManualApproval()
		guard.RecordManualApproval()

		// Jump to t=2h (all events expired)
		guard.nowFunc = func() time.Time { return now.Add(2 * time.Hour) }

		// Record 1 approval -- only 1 event in window, below min samples
		guard.RecordNonManualApproval()
		if guard.IsPaused() {
			t.Error("should not be paused after events expired")
		}
	})

	t.Run("fresh_events_within_window_still_trigger", func(t *testing.T) {
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                time.Hour,
			RejectionThresholdPct: 50,
			MinSamples:            4,
			Logger:                newTestLogger(),
		})

		now := time.Now()

		// Record 2 rejections at t=0
		guard.nowFunc = func() time.Time { return now }
		guard.RecordManualApproval()
		guard.RecordManualApproval()

		// Jump to t=30m (still within 1h window)
		guard.nowFunc = func() time.Time { return now.Add(30 * time.Minute) }
		guard.RecordManualApproval()
		guard.RecordManualApproval()
		if !guard.IsPaused() {
			t.Error("expected paused: all 4 events are within window with 100% rejection rate")
		}
	})
}

// ---------------------------------------------------------------------------
// TestSendPauseAlert
// ---------------------------------------------------------------------------

func TestSendPauseAlert(t *testing.T) {
	t.Run("no_panic_without_notify_service", func(t *testing.T) {
		// Guard without notify service should not panic
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			Logger:                newTestLogger(),
			// NotifySvc and Channel are nil
		})

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
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			ResumeAfter:           10 * time.Second, // long timer
			Logger:                newTestLogger(),
		})

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
		guard := mustCreateGuard(t, ManualApprovalGuardConfig{
			Window:                5 * time.Minute,
			RejectionThresholdPct: 1,
			MinSamples:            1,
			ResumeAfter:           100 * time.Millisecond,
			Logger:                newTestLogger(),
		})

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

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustCreateGuard(t *testing.T, cfg ManualApprovalGuardConfig) *ManualApprovalGuard {
	t.Helper()
	guard, err := NewManualApprovalGuard(cfg)
	if err != nil {
		t.Fatalf("failed to create guard: %v", err)
	}
	return guard
}
