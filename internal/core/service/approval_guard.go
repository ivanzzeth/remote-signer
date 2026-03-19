package service

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/notify"
)

// guardEvent records a single request outcome within the sliding window.
type guardEvent struct {
	ts        time.Time
	rejected  bool // true = rejection (manual-approval or rule-blocked), false = auto-approved
}

// ManualApprovalGuard pauses all sign requests when the rejection rate within a
// sliding time window exceeds a configurable threshold (and minimum sample size
// is met). This prevents the alternating-pattern bypass where an attacker
// interleaves legitimate and malicious requests to reset a consecutive counter.
//
// After resumeAfter duration it auto-resumes so the team has time to respond.
type ManualApprovalGuard struct {
	window              time.Duration
	rejectionThreshPct  float64 // 0-100 percentage
	minSamples          int
	resumeAfter         time.Duration
	notifySvc           *notify.NotifyService
	channel             *notify.Channel
	logger              *slog.Logger
	mu                  sync.Mutex
	paused              bool
	events              []guardEvent // sliding window of timestamped outcomes
	resumeTimer         *time.Timer  // nil when not paused or no auto-resume
	nowFunc             func() time.Time // for testing; defaults to time.Now
}

// ManualApprovalGuardConfig configures the guard.
type ManualApprovalGuardConfig struct {
	// Window is the sliding time window for rate calculation. Default: 1h.
	Window time.Duration
	// RejectionThresholdPct is the rejection rate percentage (0-100) that triggers pause.
	// Default: 50 (i.e. >50% rejections triggers pause).
	RejectionThresholdPct float64
	// MinSamples is the minimum number of events within the window before the
	// rejection rate check is applied. Default: 10.
	MinSamples  int
	// ResumeAfter is the pause duration after which to auto-resume (e.g. 2h); 0 = no auto-resume.
	ResumeAfter time.Duration
	NotifySvc   *notify.NotifyService
	Channel     *notify.Channel
	Logger      *slog.Logger
}

const (
	defaultWindow              = time.Hour
	defaultRejectionThreshPct  = 50.0
	defaultMinSamples          = 10
)

// NewManualApprovalGuard creates a new guard. NotifySvc and Channel may be nil when disabled.
func NewManualApprovalGuard(cfg ManualApprovalGuardConfig) (*ManualApprovalGuard, error) {
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	window := cfg.Window
	if window <= 0 {
		window = defaultWindow
	}
	threshPct := cfg.RejectionThresholdPct
	if threshPct <= 0 {
		threshPct = defaultRejectionThreshPct
	}
	if threshPct > 100 {
		return nil, fmt.Errorf("rejection threshold percentage must be <= 100, got %.1f", threshPct)
	}
	minSamples := cfg.MinSamples
	if minSamples <= 0 {
		minSamples = defaultMinSamples
	}

	g := &ManualApprovalGuard{
		window:             window,
		rejectionThreshPct: threshPct,
		minSamples:         minSamples,
		resumeAfter:        cfg.ResumeAfter,
		notifySvc:          cfg.NotifySvc,
		channel:            cfg.Channel,
		logger:             cfg.Logger,
		events:             make([]guardEvent, 0, minSamples*2),
		nowFunc:            time.Now,
	}
	return g, nil
}

// IsPaused returns true when the guard has triggered and all sign requests should be rejected.
func (g *ManualApprovalGuard) IsPaused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

// expireOldEvents removes events outside the sliding window. Call with g.mu held.
func (g *ManualApprovalGuard) expireOldEvents(now time.Time) {
	cutoff := now.Add(-g.window)
	i := 0
	for i < len(g.events) && g.events[i].ts.Before(cutoff) {
		i++
	}
	if i > 0 {
		g.events = g.events[i:]
	}
}

// checkAndMaybePause evaluates the sliding window and triggers pause if needed.
// Call with g.mu held. Returns true if pause was triggered (caller must send alert after unlocking).
func (g *ManualApprovalGuard) checkAndMaybePause(now time.Time) bool {
	g.expireOldEvents(now)

	total := len(g.events)
	if total < g.minSamples {
		return false
	}

	rejections := 0
	for _, e := range g.events {
		if e.rejected {
			rejections++
		}
	}

	rate := float64(rejections) / float64(total) * 100.0
	if rate > g.rejectionThreshPct {
		g.paused = true
		g.events = nil
		g.startResumeTimer()
		return true
	}
	return false
}

// recordOutcome adds an event to the sliding window and checks if pause should trigger.
func (g *ManualApprovalGuard) recordOutcome(rejected bool) {
	g.mu.Lock()
	now := g.nowFunc()
	g.events = append(g.events, guardEvent{ts: now, rejected: rejected})
	triggered := g.checkAndMaybePause(now)
	g.mu.Unlock()

	if triggered {
		g.sendPauseAlert()
	}
}

// RecordManualApproval records a request that required manual approval (no whitelist match).
// Counts as a rejection toward the sliding window rate calculation.
func (g *ManualApprovalGuard) RecordManualApproval() {
	g.recordOutcome(true)
}

// RecordRuleRejected records a request that was blocked by a blocklist rule.
// Counts as a rejection toward the sliding window rate calculation.
func (g *ManualApprovalGuard) RecordRuleRejected() {
	g.recordOutcome(true)
}

// RecordNonManualApproval records a request that was auto-approved.
// Counts as an approval in the sliding window (does NOT reset the window).
func (g *ManualApprovalGuard) RecordNonManualApproval() {
	g.recordOutcome(false)
}

// startResumeTimer starts a timer to auto-resume after g.resumeAfter. Call with g.mu held.
func (g *ManualApprovalGuard) startResumeTimer() {
	if g.resumeAfter <= 0 {
		return
	}
	if g.resumeTimer != nil {
		g.resumeTimer.Stop()
		g.resumeTimer = nil
	}
	g.resumeTimer = time.AfterFunc(g.resumeAfter, func() {
		g.mu.Lock()
		if !g.paused {
			g.mu.Unlock()
			return
		}
		g.resumeTimer = nil
		g.paused = false
		g.mu.Unlock()
		g.logger.Info("approval guard auto-resumed after pause duration", "resume_after", g.resumeAfter)
	})
}

// Resume clears the paused state so sign requests are accepted again.
// Call via admin API or after auto-resume timer.
func (g *ManualApprovalGuard) Resume() {
	g.mu.Lock()
	g.paused = false
	g.events = nil
	if g.resumeTimer != nil {
		g.resumeTimer.Stop()
		g.resumeTimer = nil
	}
	g.mu.Unlock()
	g.logger.Info("approval guard resumed, sign requests accepted again")
}

func (g *ManualApprovalGuard) sendPauseAlert() {
	if g.notifySvc == nil || g.channel == nil {
		g.logger.Warn("approval guard triggered but notify not configured, cannot send alert")
		return
	}
	resumeHint := "Use admin API to resume."
	if g.resumeAfter > 0 {
		resumeHint = fmt.Sprintf("Auto-resume in %s, or use admin API to resume now.", g.resumeAfter)
	}
	msg := fmt.Sprintf("[Remote Signer] Approval guard triggered: rejection rate exceeded %.0f%% (min %d samples) within %s window (possible API key abuse). All sign requests are paused. %s",
		g.rejectionThreshPct, g.minSamples, g.window, resumeHint)
	if err := g.notifySvc.Send(g.channel, msg); err != nil {
		g.logger.Error("failed to send approval guard alert", "error", err)
		return
	}
	g.logger.Warn("approval guard paused sign requests and sent alert",
		"rejection_threshold_pct", g.rejectionThreshPct,
		"min_samples", g.minSamples,
		"window", g.window,
	)
}
