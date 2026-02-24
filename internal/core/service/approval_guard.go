package service

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/notify"
)

// ManualApprovalGuard pauses all sign requests when too many consecutive
// "not auto-approved" outcomes occur within a time window (manual approval or rule-blocked),
// and sends an alert via notify. Used to detect API key abuse / brute-force: valid API key
// but requests repeatedly rejected by rules or needing manual approval.
// After resumeAfter duration it auto-resumes so the team has time to respond.
type ManualApprovalGuard struct {
	window       time.Duration
	threshold    int
	resumeAfter  time.Duration
	notifySvc    *notify.NotifyService
	channel      *notify.Channel
	logger       *slog.Logger
	mu           sync.Mutex
	paused       bool
	consecutive  []time.Time  // timestamps of consecutive rejections (manual-approval or rule-blocked)
	resumeTimer  *time.Timer  // nil when not paused or no auto-resume
}

// ManualApprovalGuardConfig configures the guard.
type ManualApprovalGuardConfig struct {
	Window      time.Duration
	Threshold   int
	ResumeAfter time.Duration // pause duration after which to auto-resume (e.g. 2h); 0 = no auto-resume
	NotifySvc   *notify.NotifyService
	Channel     *notify.Channel
	Logger      *slog.Logger
}

// NewManualApprovalGuard creates a new guard. NotifySvc and Channel may be nil when disabled.
func NewManualApprovalGuard(cfg ManualApprovalGuardConfig) (*ManualApprovalGuard, error) {
	if cfg.Threshold <= 0 {
		return nil, fmt.Errorf("approval guard threshold must be positive, got %d", cfg.Threshold)
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	g := &ManualApprovalGuard{
		window:      cfg.Window,
		threshold:   cfg.Threshold,
		resumeAfter: cfg.ResumeAfter,
		notifySvc:   cfg.NotifySvc,
		channel:     cfg.Channel,
		logger:      cfg.Logger,
		consecutive: make([]time.Time, 0, cfg.Threshold+2),
	}
	return g, nil
}

// IsPaused returns true when the guard has triggered and all sign requests should be rejected.
func (g *ManualApprovalGuard) IsPaused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

// recordRejection adds one "not auto-approved" outcome and may trigger pause. Call with g.mu not held.
func (g *ManualApprovalGuard) recordRejection() {
	g.mu.Lock()
	now := time.Now()
	g.consecutive = append(g.consecutive, now)
	for len(g.consecutive) > g.threshold {
		g.consecutive = g.consecutive[1:]
	}
	shouldPause := false
	if len(g.consecutive) >= g.threshold {
		first := g.consecutive[0]
		if g.window <= 0 || now.Sub(first) <= g.window {
			shouldPause = true
		}
	}
	if shouldPause {
		g.paused = true
		g.consecutive = nil
		g.startResumeTimer()
		g.mu.Unlock()
		g.sendPauseAlert()
		return
	}
	g.mu.Unlock()
}

// RecordManualApproval records a request that required manual approval (no whitelist match).
// Counts toward consecutive "rejection" for abuse detection.
func (g *ManualApprovalGuard) RecordManualApproval() {
	g.recordRejection()
}

// RecordRuleRejected records a request that was blocked by a blocklist rule.
// Counts toward consecutive "rejection" to detect API key abuse / brute-force via valid path.
func (g *ManualApprovalGuard) RecordRuleRejected() {
	g.recordRejection()
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

// RecordNonManualApproval resets the consecutive counter (request was auto-approved or blocked).
func (g *ManualApprovalGuard) RecordNonManualApproval() {
	g.mu.Lock()
	g.consecutive = nil
	g.mu.Unlock()
}

// Resume clears the paused state so sign requests are accepted again. Call via admin API or after auto-resume timer.
func (g *ManualApprovalGuard) Resume() {
	g.mu.Lock()
	g.paused = false
	g.consecutive = nil
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
	msg := fmt.Sprintf("[Remote Signer] Approval guard triggered: %d consecutive rejected/pending-approval requests within %s (possible API key abuse). All sign requests are paused. %s", g.threshold, g.window, resumeHint)
	if err := g.notifySvc.Send(g.channel, msg); err != nil {
		g.logger.Error("failed to send approval guard alert", "error", err)
		return
	}
	g.logger.Warn("approval guard paused sign requests and sent alert",
		"threshold", g.threshold,
		"window", g.window,
	)
}
