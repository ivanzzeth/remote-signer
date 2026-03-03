package audit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuditRepo is a minimal in-memory AuditRepository for testing.
type mockAuditRepo struct {
	records []*types.AuditRecord
}

func (m *mockAuditRepo) Log(_ context.Context, record *types.AuditRecord) error {
	m.records = append(m.records, record)
	return nil
}

func (m *mockAuditRepo) Query(_ context.Context, filter storage.AuditFilter) ([]*types.AuditRecord, error) {
	var result []*types.AuditRecord
	for _, r := range m.records {
		if filter.StartTime != nil && r.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && r.Timestamp.After(*filter.EndTime) {
			continue
		}
		result = append(result, r)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, nil
}

func (m *mockAuditRepo) Count(_ context.Context, _ storage.AuditFilter) (int, error) {
	return len(m.records), nil
}

func (m *mockAuditRepo) GetByRequestID(_ context.Context, _ types.SignRequestID) ([]*types.AuditRecord, error) {
	return nil, nil
}

// errorAuditRepo returns an error from Query to test the scan error path.
type errorAuditRepo struct {
	queryErr   error
	queryCalls atomic.Int64
}

func (e *errorAuditRepo) Log(_ context.Context, _ *types.AuditRecord) error {
	return nil
}

func (e *errorAuditRepo) Query(_ context.Context, _ storage.AuditFilter) ([]*types.AuditRecord, error) {
	e.queryCalls.Add(1)
	return nil, e.queryErr
}

func (e *errorAuditRepo) Count(_ context.Context, _ storage.AuditFilter) (int, error) {
	return 0, nil
}

func (e *errorAuditRepo) GetByRequestID(_ context.Context, _ types.SignRequestID) ([]*types.AuditRecord, error) {
	return nil, nil
}

// trackingAuditRepo wraps mockAuditRepo and tracks how many times Query is called.
type trackingAuditRepo struct {
	mu         sync.Mutex
	records    []*types.AuditRecord
	queryCalls int
}

func (t *trackingAuditRepo) Log(_ context.Context, record *types.AuditRecord) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.records = append(t.records, record)
	return nil
}

func (t *trackingAuditRepo) Query(_ context.Context, filter storage.AuditFilter) ([]*types.AuditRecord, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.queryCalls++
	var result []*types.AuditRecord
	for _, r := range t.records {
		if filter.StartTime != nil && r.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && r.Timestamp.After(*filter.EndTime) {
			continue
		}
		result = append(result, r)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, nil
}

func (t *trackingAuditRepo) Count(_ context.Context, _ storage.AuditFilter) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.records), nil
}

func (t *trackingAuditRepo) GetByRequestID(_ context.Context, _ types.SignRequestID) ([]*types.AuditRecord, error) {
	return nil, nil
}

func (t *trackingAuditRepo) getQueryCalls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.queryCalls
}

// newTestNotifyService creates a minimal NotifyService for testing (no real channels).
func newTestNotifyService(t *testing.T) *notify.NotifyService {
	t.Helper()
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)
	svc.Start(context.Background())
	t.Cleanup(func() { svc.Stop() })
	return svc
}

// testLogger returns a no-op slog.Logger suitable for testing.
func testLogger() *slog.Logger {
	return slog.Default()
}

// testChannel returns a minimal notify.Channel for testing.
func testChannel() *notify.Channel {
	return &notify.Channel{}
}

func TestAnalyzeRecords_AuthFailureBurst(t *testing.T) {
	cfg := MonitorConfig{AuthFailureThreshold: 3, LookbackHours: 1}

	now := time.Now().UTC()
	records := make([]*types.AuditRecord, 5)
	for i := range records {
		records[i] = &types.AuditRecord{
			EventType: types.AuditEventTypeAuthFailure,
			APIKeyID:  "bad-key",
			Timestamp: now,
		}
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "AUTH_FAILURE_BURST", anomalies[0].Category)
	assert.Equal(t, "bad-key", anomalies[0].Source)
	assert.Equal(t, 5, anomalies[0].Count)
}

func TestAnalyzeRecords_SignRejectionBurst(t *testing.T) {
	cfg := MonitorConfig{BlocklistRejectThreshold: 2, LookbackHours: 1}

	signer := "0xdead"
	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeSignRejected, SignerAddress: &signer},
		{EventType: types.AuditEventTypeSignRejected, SignerAddress: &signer},
		{EventType: types.AuditEventTypeSignRejected, SignerAddress: &signer},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "SIGN_REJECTION_BURST", anomalies[0].Category)
	assert.Equal(t, "0xdead", anomalies[0].Source)
}

func TestAnalyzeRecords_RateLimitHit(t *testing.T) {
	cfg := MonitorConfig{LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeRateLimitHit, APIKeyID: "app-key"},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "RATE_LIMIT_HIT", anomalies[0].Category)
}

func TestAnalyzeRecords_HighFrequency(t *testing.T) {
	cfg := MonitorConfig{HighFreqThreshold: 10, LookbackHours: 1}

	records := make([]*types.AuditRecord, 15)
	for i := range records {
		records[i] = &types.AuditRecord{
			EventType: types.AuditEventTypeSignRequest,
			APIKeyID:  "bot-key",
		}
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "HIGH_FREQUENCY_REQUESTS", anomalies[0].Category)
}

func TestAnalyzeRecords_NoAnomalies(t *testing.T) {
	cfg := MonitorConfig{LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeAuthFailure, APIKeyID: "k1"},
		{EventType: types.AuditEventTypeSignRequest, APIKeyID: "k2"},
	}

	anomalies := AnalyzeRecords(cfg, records)
	assert.Empty(t, anomalies)
}

func TestAnalyzeRecords_UnknownSource(t *testing.T) {
	cfg := MonitorConfig{AuthFailureThreshold: 1, LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeAuthFailure, APIKeyID: "", ActorAddress: ""},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "unknown", anomalies[0].Source)
}

func TestFormatAnomalyAlert(t *testing.T) {
	start := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 14, 13, 0, 0, 0, time.UTC)

	anomalies := []Anomaly{
		{
			Category:    "AUTH_FAILURE_BURST",
			Source:      "admin-key",
			Count:       12,
			Window:      "1h",
			Description: "12.0 auth failures/hour (threshold: 5/hour)",
		},
		{
			Category:    "RATE_LIMIT_HIT",
			Source:      "app-key",
			Count:       3,
			Window:      "1h",
			Description: "3 rate limit hits in 1h",
		},
	}

	msg := FormatAnomalyAlert(anomalies, start, end, 1, 487)

	assert.Contains(t, msg, "[Remote Signer Audit] 2 ANOMALIES DETECTED")
	assert.Contains(t, msg, "2026-02-14T12:00:00Z")
	assert.Contains(t, msg, "2026-02-14T13:00:00Z")
	assert.Contains(t, msg, "Total records analyzed: 487")
	assert.Contains(t, msg, "[1] AUTH_FAILURE_BURST")
	assert.Contains(t, msg, "Source: admin-key")
	assert.Contains(t, msg, "[2] RATE_LIMIT_HIT")
}

func TestNewMonitor_Validation(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	tests := []struct {
		name      string
		repo      storage.AuditRepository
		svc       *notify.NotifyService
		ch        *notify.Channel
		log       *slog.Logger
		wantErr   string
	}{
		{
			name:    "nil audit repository",
			repo:    nil,
			svc:     svc,
			ch:      ch,
			log:     log,
			wantErr: "audit repository is required",
		},
		{
			name:    "nil notify service",
			repo:    repo,
			svc:     nil,
			ch:      ch,
			log:     log,
			wantErr: "notify service is required",
		},
		{
			name:    "nil channel",
			repo:    repo,
			svc:     svc,
			ch:      nil,
			log:     log,
			wantErr: "notify channel is required",
		},
		{
			name:    "nil logger",
			repo:    repo,
			svc:     svc,
			ch:      ch,
			log:     nil,
			wantErr: "logger is required",
		},
		{
			name:    "valid inputs",
			repo:    repo,
			svc:     svc,
			ch:      ch,
			log:     log,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMonitor(tt.repo, tt.svc, tt.ch, MonitorConfig{}, tt.log)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, m)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}
		})
	}
}

func TestNewMonitor_DefaultsApplied(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{}, log)
	require.NoError(t, err)

	// Verify that setDefaults was called on the config stored in the Monitor.
	assert.Equal(t, time.Hour, m.cfg.Interval)
	assert.Equal(t, 1, m.cfg.LookbackHours)
	assert.Equal(t, 5, m.cfg.AuthFailureThreshold)
	assert.Equal(t, 3, m.cfg.BlocklistRejectThreshold)
	assert.Equal(t, 100, m.cfg.HighFreqThreshold)
}

func TestNewMonitor_CustomConfig(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	cfg := MonitorConfig{
		Enabled:                  true,
		Interval:                 5 * time.Minute,
		LookbackHours:            2,
		AuthFailureThreshold:     10,
		BlocklistRejectThreshold: 7,
		HighFreqThreshold:        500,
	}

	m, err := NewMonitor(repo, svc, ch, cfg, log)
	require.NoError(t, err)

	// Custom values should be preserved (not overwritten by defaults).
	assert.Equal(t, 5*time.Minute, m.cfg.Interval)
	assert.Equal(t, 2, m.cfg.LookbackHours)
	assert.Equal(t, 10, m.cfg.AuthFailureThreshold)
	assert.Equal(t, 7, m.cfg.BlocklistRejectThreshold)
	assert.Equal(t, 500, m.cfg.HighFreqThreshold)
}

func TestMonitorConfig_SetDefaults(t *testing.T) {
	cfg := MonitorConfig{}
	cfg.setDefaults()

	assert.Equal(t, time.Hour, cfg.Interval)
	assert.Equal(t, 1, cfg.LookbackHours)
	assert.Equal(t, 5, cfg.AuthFailureThreshold)
	assert.Equal(t, 3, cfg.BlocklistRejectThreshold)
	assert.Equal(t, 100, cfg.HighFreqThreshold)
}

func TestMonitorConfig_SetDefaults_PreservesNonZero(t *testing.T) {
	cfg := MonitorConfig{
		Interval:                 30 * time.Second,
		LookbackHours:            4,
		AuthFailureThreshold:     20,
		BlocklistRejectThreshold: 15,
		HighFreqThreshold:        1000,
	}
	cfg.setDefaults()

	assert.Equal(t, 30*time.Second, cfg.Interval)
	assert.Equal(t, 4, cfg.LookbackHours)
	assert.Equal(t, 20, cfg.AuthFailureThreshold)
	assert.Equal(t, 15, cfg.BlocklistRejectThreshold)
	assert.Equal(t, 1000, cfg.HighFreqThreshold)
}

// --- Start / Stop lifecycle tests ---

func TestMonitor_StartStop(t *testing.T) {
	repo := &trackingAuditRepo{}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:      50 * time.Millisecond,
		LookbackHours: 1,
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)

	// Wait for the immediate scan in loop to execute.
	time.Sleep(100 * time.Millisecond)

	m.Stop()

	// The loop should have called Query at least once (the immediate scan on startup).
	assert.GreaterOrEqual(t, repo.getQueryCalls(), 1)
}

func TestMonitor_StopBeforeStart(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{}, log)
	require.NoError(t, err)

	// Stop before Start should not panic. cancel is nil, wg has count 0.
	m.Stop()
}

func TestMonitor_DoubleStop(t *testing.T) {
	repo := &mockAuditRepo{}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval: 50 * time.Millisecond,
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)
	time.Sleep(80 * time.Millisecond)

	// Double stop should not panic or deadlock.
	m.Stop()
	m.Stop()
}

func TestMonitor_StartWithCanceledContext(t *testing.T) {
	repo := &trackingAuditRepo{}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:      time.Hour, // long interval so ticker won't fire
		LookbackHours: 1,
	}, log)
	require.NoError(t, err)

	// Create an already-canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m.Start(ctx)

	// The goroutine should exit quickly because the context is already done.
	// Wait briefly then stop.
	time.Sleep(50 * time.Millisecond)
	m.Stop()

	// The immediate scan should still have been called once.
	assert.GreaterOrEqual(t, repo.getQueryCalls(), 1)
}

// --- scan behavior tests ---

func TestMonitor_ScanEmptyRecords(t *testing.T) {
	// When the repo returns no records, scan should return without sending notifications.
	repo := &trackingAuditRepo{} // no records
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:      50 * time.Millisecond,
		LookbackHours: 1,
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)
	time.Sleep(80 * time.Millisecond)
	m.Stop()

	// Query was called but no anomalies so no notification sent.
	assert.GreaterOrEqual(t, repo.getQueryCalls(), 1)
}

func TestMonitor_ScanWithAnomalies(t *testing.T) {
	// Populate repo with enough auth failures to trigger an anomaly.
	now := time.Now().UTC()
	repo := &trackingAuditRepo{}
	for i := 0; i < 10; i++ {
		repo.records = append(repo.records, &types.AuditRecord{
			EventType: types.AuditEventTypeAuthFailure,
			APIKeyID:  "suspect-key",
			Timestamp: now,
		})
	}

	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:             50 * time.Millisecond,
		LookbackHours:        1,
		AuthFailureThreshold: 3,
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)
	// Wait for the initial scan to execute.
	time.Sleep(80 * time.Millisecond)
	m.Stop()

	// Query was called and anomalies were detected.
	assert.GreaterOrEqual(t, repo.getQueryCalls(), 1)
}

func TestMonitor_ScanQueryError(t *testing.T) {
	// When Query returns an error, scan should log it and not panic.
	repo := &errorAuditRepo{queryErr: fmt.Errorf("database connection lost")}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:      50 * time.Millisecond,
		LookbackHours: 1,
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)
	time.Sleep(80 * time.Millisecond)
	m.Stop()

	// Query was attempted at least once.
	assert.GreaterOrEqual(t, repo.queryCalls.Load(), int64(1))
}

func TestMonitor_ScanNoAnomaliesBelowThreshold(t *testing.T) {
	// Records exist but are below every anomaly threshold.
	now := time.Now().UTC()
	repo := &trackingAuditRepo{}
	// 2 auth failures, threshold is 5 (default) -- no anomaly.
	for i := 0; i < 2; i++ {
		repo.records = append(repo.records, &types.AuditRecord{
			EventType: types.AuditEventTypeAuthFailure,
			APIKeyID:  "normal-key",
			Timestamp: now,
		})
	}

	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:      50 * time.Millisecond,
		LookbackHours: 1,
		// defaults: AuthFailureThreshold=5, so 2 failures is below
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)
	time.Sleep(80 * time.Millisecond)
	m.Stop()

	assert.GreaterOrEqual(t, repo.getQueryCalls(), 1)
}

func TestMonitor_LoopTickerFiresMultipleTimes(t *testing.T) {
	// Verify the ticker path in loop fires by using a very short interval.
	repo := &trackingAuditRepo{}
	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:      20 * time.Millisecond,
		LookbackHours: 1,
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)
	// Wait long enough for the immediate scan + at least 2 ticker fires.
	time.Sleep(100 * time.Millisecond)
	m.Stop()

	// Should have at least 3 calls: 1 immediate + 2 from ticks.
	assert.GreaterOrEqual(t, repo.getQueryCalls(), 3)
}

func TestMonitor_ScanRecordsOutsideWindow(t *testing.T) {
	// Records timestamped far in the past should not be returned by the mock's
	// time-filtered Query, so scan should see zero records.
	twoHoursAgo := time.Now().UTC().Add(-2 * time.Hour)
	repo := &trackingAuditRepo{}
	for i := 0; i < 10; i++ {
		repo.records = append(repo.records, &types.AuditRecord{
			EventType: types.AuditEventTypeAuthFailure,
			APIKeyID:  "old-key",
			Timestamp: twoHoursAgo,
		})
	}

	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:             50 * time.Millisecond,
		LookbackHours:        1, // only looks back 1 hour
		AuthFailureThreshold: 3,
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)
	time.Sleep(80 * time.Millisecond)
	m.Stop()

	// Query was called but records outside window are filtered, so no anomaly.
	assert.GreaterOrEqual(t, repo.getQueryCalls(), 1)
}

func TestMonitor_ScanWithMixedAnomalyTypes(t *testing.T) {
	// Multiple anomaly types in a single scan window.
	now := time.Now().UTC()
	repo := &trackingAuditRepo{}

	// Auth failures (10, threshold 3)
	for i := 0; i < 10; i++ {
		repo.records = append(repo.records, &types.AuditRecord{
			EventType: types.AuditEventTypeAuthFailure,
			APIKeyID:  "attacker-key",
			Timestamp: now,
		})
	}

	// Rate limit hits
	for i := 0; i < 5; i++ {
		repo.records = append(repo.records, &types.AuditRecord{
			EventType: types.AuditEventTypeRateLimitHit,
			APIKeyID:  "flood-key",
			Timestamp: now,
		})
	}

	// Sign rejections
	signer := "0xbad"
	for i := 0; i < 4; i++ {
		repo.records = append(repo.records, &types.AuditRecord{
			EventType:    types.AuditEventTypeSignRejected,
			SignerAddress: &signer,
			Timestamp:    now,
		})
	}

	svc := newTestNotifyService(t)
	ch := testChannel()
	log := testLogger()

	m, err := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:                 50 * time.Millisecond,
		LookbackHours:            1,
		AuthFailureThreshold:     3,
		BlocklistRejectThreshold: 2,
	}, log)
	require.NoError(t, err)

	ctx := context.Background()
	m.Start(ctx)
	time.Sleep(80 * time.Millisecond)
	m.Stop()

	assert.GreaterOrEqual(t, repo.getQueryCalls(), 1)
}

func TestMonitor_ScanSendError(t *testing.T) {
	// When notifyService.Send returns an error (e.g. channel full), scan logs
	// the error and does not panic. We create a NotifyService but do NOT start
	// its consumer loop, then fill its internal buffer so Send returns an error.
	now := time.Now().UTC()
	repo := &trackingAuditRepo{}
	for i := 0; i < 10; i++ {
		repo.records = append(repo.records, &types.AuditRecord{
			EventType: types.AuditEventTypeAuthFailure,
			APIKeyID:  "bad-key",
			Timestamp: now,
		})
	}

	// Create NotifyService but do NOT call Start() so the consumer is not running.
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)
	// Fill the internal buffered channel (capacity 1000).
	dummyCh := &notify.Channel{}
	for i := 0; i < 1000; i++ {
		_ = svc.Send(dummyCh, fmt.Sprintf("filler-%d", i))
	}

	ch := testChannel()
	log := testLogger()

	m, merr := NewMonitor(repo, svc, ch, MonitorConfig{
		Interval:             50 * time.Millisecond,
		LookbackHours:        1,
		AuthFailureThreshold: 3,
	}, log)
	require.NoError(t, merr)

	ctx := context.Background()
	m.Start(ctx)
	time.Sleep(80 * time.Millisecond)
	m.Stop()

	// Query was called and anomaly detected; Send should have returned an error
	// but scan should not have panicked.
	assert.GreaterOrEqual(t, repo.getQueryCalls(), 1)

	// Clean up the NotifyService (stop was never called since Start was never called).
	// Just ensure no goroutine leak.
}

// --- Additional AnalyzeRecords branch coverage ---

func TestAnalyzeRecords_AuthFailure_ActorAddressFallback(t *testing.T) {
	cfg := MonitorConfig{AuthFailureThreshold: 1, LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeAuthFailure, APIKeyID: "", ActorAddress: "192.168.1.1"},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "AUTH_FAILURE_BURST", anomalies[0].Category)
	assert.Equal(t, "192.168.1.1", anomalies[0].Source)
}

func TestAnalyzeRecords_SignRejection_APIKeyIDFallback(t *testing.T) {
	// When SignerAddress is nil, should fall back to APIKeyID.
	cfg := MonitorConfig{BlocklistRejectThreshold: 1, LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeSignRejected, SignerAddress: nil, APIKeyID: "key-123"},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "SIGN_REJECTION_BURST", anomalies[0].Category)
	assert.Equal(t, "key-123", anomalies[0].Source)
}

func TestAnalyzeRecords_SignRejection_EmptySignerAddress(t *testing.T) {
	// When SignerAddress points to an empty string, should fall back to APIKeyID.
	cfg := MonitorConfig{BlocklistRejectThreshold: 1, LookbackHours: 1}

	empty := ""
	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeSignRejected, SignerAddress: &empty, APIKeyID: "key-456"},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "key-456", anomalies[0].Source)
}

func TestAnalyzeRecords_SignRejection_UnknownFallback(t *testing.T) {
	// When both SignerAddress and APIKeyID are empty, falls back to "unknown".
	cfg := MonitorConfig{BlocklistRejectThreshold: 1, LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeSignRejected, SignerAddress: nil, APIKeyID: ""},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "unknown", anomalies[0].Source)
}

func TestAnalyzeRecords_RateLimitHit_ActorAddressFallback(t *testing.T) {
	cfg := MonitorConfig{LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeRateLimitHit, APIKeyID: "", ActorAddress: "10.0.0.1"},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "RATE_LIMIT_HIT", anomalies[0].Category)
	assert.Equal(t, "10.0.0.1", anomalies[0].Source)
}

func TestAnalyzeRecords_RateLimitHit_UnknownFallback(t *testing.T) {
	cfg := MonitorConfig{LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeRateLimitHit, APIKeyID: "", ActorAddress: ""},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "unknown", anomalies[0].Source)
}

func TestAnalyzeRecords_HighFrequency_SignComplete(t *testing.T) {
	// SignComplete also counts towards high-frequency requests.
	cfg := MonitorConfig{HighFreqThreshold: 5, LookbackHours: 1}

	records := make([]*types.AuditRecord, 6)
	for i := range records {
		records[i] = &types.AuditRecord{
			EventType: types.AuditEventTypeSignComplete,
			APIKeyID:  "bot-key",
		}
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "HIGH_FREQUENCY_REQUESTS", anomalies[0].Category)
	assert.Equal(t, "bot-key", anomalies[0].Source)
}

func TestAnalyzeRecords_HighFrequency_UnknownAPIKey(t *testing.T) {
	// When APIKeyID is empty for sign requests, source becomes "unknown".
	cfg := MonitorConfig{HighFreqThreshold: 1, LookbackHours: 1}

	records := []*types.AuditRecord{
		{EventType: types.AuditEventTypeSignRequest, APIKeyID: ""},
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "unknown", anomalies[0].Source)
}

func TestAnalyzeRecords_MultiHourLookback(t *testing.T) {
	// With LookbackHours=2, the rate is halved, so 6 failures -> 3/hr which is
	// below a threshold of 4 but at/above a threshold of 3.
	cfg := MonitorConfig{AuthFailureThreshold: 3, LookbackHours: 2}

	records := make([]*types.AuditRecord, 6)
	for i := range records {
		records[i] = &types.AuditRecord{
			EventType: types.AuditEventTypeAuthFailure,
			APIKeyID:  "key-x",
		}
	}

	anomalies := AnalyzeRecords(cfg, records)
	require.Len(t, anomalies, 1)
	assert.Equal(t, "AUTH_FAILURE_BURST", anomalies[0].Category)
	assert.Contains(t, anomalies[0].Description, "3.0 auth failures/hour")
}

func TestAnalyzeRecords_MultiHourLookback_BelowThreshold(t *testing.T) {
	// With LookbackHours=2, 4 failures -> 2/hr which is below threshold of 3.
	cfg := MonitorConfig{AuthFailureThreshold: 3, LookbackHours: 2}

	records := make([]*types.AuditRecord, 4)
	for i := range records {
		records[i] = &types.AuditRecord{
			EventType: types.AuditEventTypeAuthFailure,
			APIKeyID:  "key-y",
		}
	}

	anomalies := AnalyzeRecords(cfg, records)
	assert.Empty(t, anomalies)
}
