// Package audit provides a background monitor that periodically scans audit
// records for anomaly patterns and sends notifications when thresholds are
// exceeded.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// Anomaly tracks a detected anomaly pattern.
type Anomaly struct {
	Category    string
	Source      string
	Count       int
	Window      string
	Description string
}

// MonitorConfig configures the background audit monitor.
type MonitorConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Interval      time.Duration `yaml:"interval"`       // scan interval (default: 1h)
	LookbackHours int           `yaml:"lookback_hours"` // hours to look back per scan (default: 1)
	// Thresholds
	AuthFailureThreshold     int `yaml:"auth_failure_threshold"`     // per source per hour (default: 5)
	BlocklistRejectThreshold int `yaml:"blocklist_reject_threshold"` // per key per hour (default: 3)
	HighFreqThreshold        int `yaml:"high_freq_threshold"`        // requests per hour (default: 100)
	// Retention: automatically delete audit records older than RetentionDays.
	// Default: 90 days. Set to 0 to disable cleanup.
	RetentionDays    int           `yaml:"retention_days"`
	CleanupInterval  time.Duration `yaml:"cleanup_interval"` // how often to run cleanup (default: 24h)
}

func (c *MonitorConfig) setDefaults() {
	if c.Interval == 0 {
		c.Interval = time.Hour
	}
	if c.LookbackHours == 0 {
		c.LookbackHours = 1
	}
	if c.AuthFailureThreshold == 0 {
		c.AuthFailureThreshold = 5
	}
	if c.BlocklistRejectThreshold == 0 {
		c.BlocklistRejectThreshold = 3
	}
	if c.HighFreqThreshold == 0 {
		c.HighFreqThreshold = 100
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 90
	}
	if c.CleanupInterval == 0 {
		c.CleanupInterval = 24 * time.Hour
	}
}

// Monitor is a background goroutine that periodically queries audit records
// for anomaly patterns and sends alerts via NotifyService.
type Monitor struct {
	auditRepo     storage.AuditRepository
	notifyService *notify.NotifyService
	channel       *notify.Channel
	cfg           MonitorConfig
	log           *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewMonitor creates a new audit monitor. Call Start() to begin scanning.
func NewMonitor(
	auditRepo storage.AuditRepository,
	notifyService *notify.NotifyService,
	channel *notify.Channel,
	cfg MonitorConfig,
	log *slog.Logger,
) (*Monitor, error) {
	if auditRepo == nil {
		return nil, fmt.Errorf("audit repository is required")
	}
	if notifyService == nil {
		return nil, fmt.Errorf("notify service is required")
	}
	if channel == nil {
		return nil, fmt.Errorf("notify channel is required")
	}
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}

	cfg.setDefaults()

	return &Monitor{
		auditRepo:     auditRepo,
		notifyService: notifyService,
		channel:       channel,
		cfg:           cfg,
		log:           log,
	}, nil
}

// Start launches the background scanning goroutine.
func (m *Monitor) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.loop(ctx)
	m.log.Info("Audit monitor started",
		"interval", m.cfg.Interval,
		"lookback_hours", m.cfg.LookbackHours,
	)
}

// Stop signals the monitor to stop and waits for it to finish.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info("Audit monitor stopped")
}

func (m *Monitor) loop(ctx context.Context) {
	defer m.wg.Done()

	// Run an immediate scan on startup, then on each tick.
	m.scan(ctx)

	scanTicker := time.NewTicker(m.cfg.Interval)
	defer scanTicker.Stop()

	cleanupTicker := time.NewTicker(m.cfg.CleanupInterval)
	defer cleanupTicker.Stop()
	// Run initial cleanup after a short delay (don't block startup scan)
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
			m.cleanup(ctx)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-scanTicker.C:
			m.scan(ctx)
		case <-cleanupTicker.C:
			m.cleanup(ctx)
		}
	}
}

func (m *Monitor) scan(ctx context.Context) {
	now := time.Now().UTC()
	start := now.Add(-time.Duration(m.cfg.LookbackHours) * time.Hour)

	records, err := m.auditRepo.Query(ctx, storage.AuditFilter{
		StartTime: &start,
		EndTime:   &now,
		Limit:     10000, // large enough to cover one scan window
	})
	if err != nil {
		m.log.Error("Audit monitor scan failed", "error", err)
		return
	}

	m.log.Debug("Audit monitor scanned records",
		"count", len(records),
		"start", start.Format(time.RFC3339),
		"end", now.Format(time.RFC3339),
	)

	if len(records) == 0 {
		return
	}

	anomalies := AnalyzeRecords(m.cfg, records)
	if len(anomalies) == 0 {
		return
	}

	message := FormatAnomalyAlert(anomalies, start, now, m.cfg.LookbackHours, len(records))
	if err := m.notifyService.Send(m.channel, message); err != nil {
		m.log.Error("Failed to send audit anomaly notification", "error", err)
	} else {
		m.log.Warn("Audit anomalies detected and notified",
			"anomaly_count", len(anomalies),
			"record_count", len(records),
		)
	}
}

// AnalyzeRecords examines audit records and returns detected anomalies based on
// the provided configuration thresholds. It is used by both the background
// Monitor and the one-shot CLI.
func AnalyzeRecords(cfg MonitorConfig, records []*types.AuditRecord) []Anomaly {
	cfg.setDefaults()
	window := fmt.Sprintf("%dh", cfg.LookbackHours)
	hours := cfg.LookbackHours

	authFailures := make(map[string]int)
	signRejections := make(map[string]int)
	rateLimitHits := make(map[string]int)
	requestCounts := make(map[string]int)

	for _, r := range records {
		switch r.EventType {
		case types.AuditEventTypeAuthFailure:
			source := r.APIKeyID
			if source == "" {
				source = r.ActorAddress
			}
			if source == "" {
				source = "unknown"
			}
			authFailures[source]++

		case types.AuditEventTypeSignRejected:
			key := ""
			if r.SignerAddress != nil {
				key = *r.SignerAddress
			}
			if key == "" {
				key = r.APIKeyID
			}
			if key == "" {
				key = "unknown"
			}
			signRejections[key]++

		case types.AuditEventTypeRateLimitHit:
			source := r.APIKeyID
			if source == "" {
				source = r.ActorAddress
			}
			if source == "" {
				source = "unknown"
			}
			rateLimitHits[source]++

		case types.AuditEventTypeSignRequest, types.AuditEventTypeSignComplete:
			source := r.APIKeyID
			if source == "" {
				source = "unknown"
			}
			requestCounts[source]++
		}
	}

	var anomalies []Anomaly

	for source, count := range authFailures {
		rate := float64(count) / float64(hours)
		if rate >= float64(cfg.AuthFailureThreshold) {
			anomalies = append(anomalies, Anomaly{
				Category:    "AUTH_FAILURE_BURST",
				Source:      source,
				Count:       count,
				Window:      window,
				Description: fmt.Sprintf("%.1f auth failures/hour (threshold: %d/hour)", rate, cfg.AuthFailureThreshold),
			})
		}
	}

	for key, count := range signRejections {
		rate := float64(count) / float64(hours)
		if rate >= float64(cfg.BlocklistRejectThreshold) {
			anomalies = append(anomalies, Anomaly{
				Category:    "SIGN_REJECTION_BURST",
				Source:      key,
				Count:       count,
				Window:      window,
				Description: fmt.Sprintf("%.1f sign rejections/hour (threshold: %d/hour)", rate, cfg.BlocklistRejectThreshold),
			})
		}
	}

	for source, count := range rateLimitHits {
		anomalies = append(anomalies, Anomaly{
			Category:    "RATE_LIMIT_HIT",
			Source:      source,
			Count:       count,
			Window:      window,
			Description: fmt.Sprintf("%d rate limit hits in %s", count, window),
		})
	}

	for source, count := range requestCounts {
		rate := float64(count) / float64(hours)
		if rate >= float64(cfg.HighFreqThreshold) {
			anomalies = append(anomalies, Anomaly{
				Category:    "HIGH_FREQUENCY_REQUESTS",
				Source:      source,
				Count:       count,
				Window:      window,
				Description: fmt.Sprintf("%.1f requests/hour from this source", rate),
			})
		}
	}

	return anomalies
}

func (m *Monitor) cleanup(ctx context.Context) {
	if m.cfg.RetentionDays <= 0 {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -m.cfg.RetentionDays)
	deleted, err := m.auditRepo.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		m.log.Error("Audit cleanup failed", "error", err)
		return
	}
	if deleted > 0 {
		m.log.Info("Audit cleanup completed",
			"deleted", deleted,
			"retention_days", m.cfg.RetentionDays,
		)
	}
}

// FormatAnomalyAlert builds a human-readable notification message.
func FormatAnomalyAlert(anomalies []Anomaly, start, end time.Time, lookbackHours, totalRecords int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Remote Signer Audit] %d ANOMALIES DETECTED\n", len(anomalies))
	fmt.Fprintf(&b, "Time window: %s to %s (%dh)\n", start.Format(time.RFC3339), end.Format(time.RFC3339), lookbackHours)
	fmt.Fprintf(&b, "Total records analyzed: %d\n", totalRecords)

	for i, a := range anomalies {
		fmt.Fprintf(&b, "\n[%d] %s\n", i+1, a.Category)
		fmt.Fprintf(&b, "    Source: %s\n", a.Source)
		fmt.Fprintf(&b, "    Count: %d in %s\n", a.Count, a.Window)
		fmt.Fprintf(&b, "    Detail: %s\n", a.Description)
	}

	return b.String()
}
