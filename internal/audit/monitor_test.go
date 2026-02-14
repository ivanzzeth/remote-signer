package audit

import (
	"context"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
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

	_, err := NewMonitor(nil, nil, nil, MonitorConfig{}, nil)
	assert.ErrorContains(t, err, "audit repository is required")

	_, err = NewMonitor(repo, nil, nil, MonitorConfig{}, nil)
	assert.ErrorContains(t, err, "notify service is required")
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
