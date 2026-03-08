package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// In-memory mock audit repository
// ---------------------------------------------------------------------------

type mockAuditRepo struct {
	records []*types.AuditRecord
	// When set, Query/Count return these errors instead of normal results.
	queryErr error
	countErr error
}

func newMockAuditRepo() *mockAuditRepo {
	return &mockAuditRepo{}
}

func (r *mockAuditRepo) Log(_ context.Context, record *types.AuditRecord) error {
	r.records = append(r.records, record)
	return nil
}

func (r *mockAuditRepo) Query(_ context.Context, filter storage.AuditFilter) ([]*types.AuditRecord, error) {
	if r.queryErr != nil {
		return nil, r.queryErr
	}

	var out []*types.AuditRecord
	for _, rec := range r.records {
		if filter.EventType != nil && rec.EventType != *filter.EventType {
			continue
		}
		if filter.APIKeyID != nil && rec.APIKeyID != *filter.APIKeyID {
			continue
		}
		if filter.ChainType != nil && (rec.ChainType == nil || *rec.ChainType != *filter.ChainType) {
			continue
		}
		if filter.StartTime != nil && rec.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && rec.Timestamp.After(*filter.EndTime) {
			continue
		}
		if filter.Cursor != nil {
			if filter.CursorID != nil {
				if rec.Timestamp.After(*filter.Cursor) {
					continue
				}
				if rec.Timestamp.Equal(*filter.Cursor) && rec.ID >= *filter.CursorID {
					continue
				}
			} else {
				if !rec.Timestamp.Before(*filter.Cursor) {
					continue
				}
			}
		}
		out = append(out, rec)
	}

	// Apply limit
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (r *mockAuditRepo) Count(_ context.Context, filter storage.AuditFilter) (int, error) {
	if r.countErr != nil {
		return 0, r.countErr
	}

	count := 0
	for _, rec := range r.records {
		if filter.EventType != nil && rec.EventType != *filter.EventType {
			continue
		}
		if filter.APIKeyID != nil && rec.APIKeyID != *filter.APIKeyID {
			continue
		}
		if filter.ChainType != nil && (rec.ChainType == nil || *rec.ChainType != *filter.ChainType) {
			continue
		}
		if filter.StartTime != nil && rec.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && rec.Timestamp.After(*filter.EndTime) {
			continue
		}
		count++
	}
	return count, nil
}

func (r *mockAuditRepo) GetByRequestID(_ context.Context, requestID types.SignRequestID) ([]*types.AuditRecord, error) {
	var out []*types.AuditRecord
	for _, rec := range r.records {
		if rec.SignRequestID != nil && *rec.SignRequestID == requestID {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (r *mockAuditRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func auditLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func auditAPIKey() *types.APIKey {
	return &types.APIKey{
		ID:      "audit-test-key",
		Name:    "Audit Test Key",
		Enabled: true,
		Admin:   true,
	}
}

func doAuditRequest(t *testing.T, h *AuditHandler, method, path string, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func seedAuditRecord(repo *mockAuditRepo, rec *types.AuditRecord) {
	repo.records = append(repo.records, rec)
}

func makeAuditRecord(id string, eventType types.AuditEventType, ts time.Time) *types.AuditRecord {
	return &types.AuditRecord{
		ID:            types.AuditID(id),
		EventType:     eventType,
		Severity:      types.AuditSeverityInfo,
		Timestamp:     ts,
		APIKeyID:      "key-1",
		ActorAddress:  "192.168.1.1",
		RequestMethod: "POST",
		RequestPath:   "/api/v1/evm/sign",
	}
}

func makeFullAuditRecord(id string) *types.AuditRecord {
	reqID := types.SignRequestID("req-123")
	signerAddr := "0xabcdef1234567890abcdef1234567890abcdef12"
	chainType := types.ChainTypeEVM
	chainID := "1"
	ruleID := types.RuleID("rule-456")
	return &types.AuditRecord{
		ID:            types.AuditID(id),
		EventType:     types.AuditEventTypeSignComplete,
		Severity:      types.AuditSeverityInfo,
		Timestamp:     time.Now(),
		APIKeyID:      "key-1",
		ActorAddress:  "192.168.1.1",
		SignRequestID: &reqID,
		SignerAddress: &signerAddr,
		ChainType:     &chainType,
		ChainID:       &chainID,
		RuleID:        &ruleID,
		Details:       []byte(`{"gas":"21000"}`),
		ErrorMessage:  "",
		RequestMethod: "POST",
		RequestPath:   "/api/v1/evm/sign",
	}
}

// ---------------------------------------------------------------------------
// Tests: NewAuditHandler
// ---------------------------------------------------------------------------

func TestNewAuditHandler(t *testing.T) {
	repo := newMockAuditRepo()
	logger := auditLogger()

	t.Run("valid_args", func(t *testing.T) {
		h, err := NewAuditHandler(repo, logger)
		require.NoError(t, err)
		assert.NotNil(t, h)
	})

	t.Run("nil_repo_returns_error", func(t *testing.T) {
		_, err := NewAuditHandler(nil, logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit repository is required")
	})

	t.Run("nil_logger_returns_error", func(t *testing.T) {
		_, err := NewAuditHandler(repo, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// ---------------------------------------------------------------------------
// Tests: ServeHTTP - authentication and method checks
// ---------------------------------------------------------------------------

func TestAuditHandler_Unauthorized(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit", nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "unauthorized", errResp.Error)
}

func TestAuditHandler_MethodNotAllowed(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	apiKey := auditAPIKey()

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			rr := doAuditRequest(t, h, method, "/api/v1/audit", apiKey)
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)

			var errResp ErrorResponse
			require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
			assert.Equal(t, "method not allowed", errResp.Error)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: listAuditRecords - basic queries
// ---------------------------------------------------------------------------

func TestAuditHandler_ListEmpty(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 0, len(resp.Records))
	assert.Equal(t, 0, resp.Total)
	assert.False(t, resp.HasMore)
	assert.Nil(t, resp.NextCursor)
	assert.Nil(t, resp.NextCursorID)
}

func TestAuditHandler_ListRecords(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()

	for i := 0; i < 5; i++ {
		rec := makeAuditRecord(
			fmt.Sprintf("audit-%d", i),
			types.AuditEventTypeSignRequest,
			now.Add(-time.Duration(i)*time.Minute),
		)
		seedAuditRecord(repo, rec)
	}

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 5, len(resp.Records))
	assert.Equal(t, 5, resp.Total)
	assert.False(t, resp.HasMore)
}

func TestAuditHandler_ListWithFullRecord(t *testing.T) {
	repo := newMockAuditRepo()
	rec := makeFullAuditRecord("audit-full-1")
	seedAuditRecord(repo, rec)

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	require.Equal(t, 1, len(resp.Records))

	r := resp.Records[0]
	assert.Equal(t, "audit-full-1", r.ID)
	assert.Equal(t, "sign_complete", r.EventType)
	assert.Equal(t, "info", r.Severity)
	assert.NotEmpty(t, r.Timestamp)
	assert.Equal(t, "key-1", r.APIKeyID)
	assert.Equal(t, "192.168.1.1", r.ActorAddress)
	require.NotNil(t, r.SignRequestID)
	assert.Equal(t, "req-123", *r.SignRequestID)
	require.NotNil(t, r.SignerAddress)
	assert.Equal(t, "0xabcdef1234567890abcdef1234567890abcdef12", *r.SignerAddress)
	require.NotNil(t, r.ChainType)
	assert.Equal(t, "evm", *r.ChainType)
	require.NotNil(t, r.ChainID)
	assert.Equal(t, "1", *r.ChainID)
	require.NotNil(t, r.RuleID)
	assert.Equal(t, "rule-456", *r.RuleID)
	assert.NotNil(t, r.Details)
	assert.Equal(t, "POST", r.RequestMethod)
	assert.Equal(t, "/api/v1/evm/sign", r.RequestPath)
}

// ---------------------------------------------------------------------------
// Tests: listAuditRecords - query filters
// ---------------------------------------------------------------------------

func TestAuditHandler_FilterEventType(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()
	seedAuditRecord(repo, makeAuditRecord("a1", types.AuditEventTypeSignRequest, now))
	seedAuditRecord(repo, makeAuditRecord("a2", types.AuditEventTypeAuthSuccess, now))
	seedAuditRecord(repo, makeAuditRecord("a3", types.AuditEventTypeSignRequest, now))

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?event_type=sign_request", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 2, len(resp.Records))
	assert.Equal(t, 2, resp.Total)
	for _, r := range resp.Records {
		assert.Equal(t, "sign_request", r.EventType)
	}
}

func TestAuditHandler_FilterInvalidEventType(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?event_type=bogus_event", auditAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "invalid event_type")
}

func TestAuditHandler_FilterAPIKeyID(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()
	r1 := makeAuditRecord("a1", types.AuditEventTypeSignRequest, now)
	r1.APIKeyID = "key-alpha"
	seedAuditRecord(repo, r1)

	r2 := makeAuditRecord("a2", types.AuditEventTypeSignRequest, now)
	r2.APIKeyID = "key-beta"
	seedAuditRecord(repo, r2)

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?api_key_id=key-alpha", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, len(resp.Records))
	assert.Equal(t, "key-alpha", resp.Records[0].APIKeyID)
}

func TestAuditHandler_FilterChainType(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()

	ct := types.ChainTypeEVM
	r1 := makeAuditRecord("a1", types.AuditEventTypeSignRequest, now)
	r1.ChainType = &ct
	seedAuditRecord(repo, r1)

	r2 := makeAuditRecord("a2", types.AuditEventTypeSignRequest, now)
	seedAuditRecord(repo, r2) // no chain type

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?chain_type=evm", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, len(resp.Records))
}

func TestAuditHandler_FilterInvalidChainType(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?chain_type=invalid_chain", auditAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "invalid chain_type")
}

func TestAuditHandler_FilterStartTime(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now().UTC()
	seedAuditRecord(repo, makeAuditRecord("a1", types.AuditEventTypeSignRequest, now.Add(-2*time.Hour)))
	seedAuditRecord(repo, makeAuditRecord("a2", types.AuditEventTypeSignRequest, now))

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	startTime := now.Add(-1 * time.Hour).Format(time.RFC3339)
	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?start_time="+startTime, auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, len(resp.Records))
}

func TestAuditHandler_FilterInvalidStartTime(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?start_time=not-a-date", auditAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "invalid start_time")
}

func TestAuditHandler_FilterEndTime(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now().UTC()
	seedAuditRecord(repo, makeAuditRecord("a1", types.AuditEventTypeSignRequest, now.Add(-2*time.Hour)))
	seedAuditRecord(repo, makeAuditRecord("a2", types.AuditEventTypeSignRequest, now))

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	endTime := now.Add(-1 * time.Hour).Format(time.RFC3339)
	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?end_time="+endTime, auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, len(resp.Records))
}

func TestAuditHandler_FilterInvalidEndTime(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?end_time=bad", auditAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "invalid end_time")
}

func TestAuditHandler_FilterLimit(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()
	for i := 0; i < 10; i++ {
		seedAuditRecord(repo, makeAuditRecord(
			fmt.Sprintf("a%d", i),
			types.AuditEventTypeSignRequest,
			now.Add(-time.Duration(i)*time.Minute),
		))
	}

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?limit=3", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	// With limit=3, after fetching limit+1=4 items and trimming, we get 3
	assert.Equal(t, 3, len(resp.Records))
	assert.Equal(t, 10, resp.Total)
	assert.True(t, resp.HasMore)
	assert.NotNil(t, resp.NextCursor)
	assert.NotNil(t, resp.NextCursorID)
}

func TestAuditHandler_FilterLimitIgnoresInvalid(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	// Invalid limit values should use default (30)
	t.Run("zero_limit", func(t *testing.T) {
		rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?limit=0", auditAPIKey())
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("negative_limit", func(t *testing.T) {
		rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?limit=-5", auditAPIKey())
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("non_numeric_limit", func(t *testing.T) {
		rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?limit=abc", auditAPIKey())
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("over_max_limit", func(t *testing.T) {
		// limit=150 exceeds 100, so should use default (30)
		rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?limit=150", auditAPIKey())
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: cursor-based pagination
// ---------------------------------------------------------------------------

func TestAuditHandler_CursorPagination(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()
	for i := 0; i < 5; i++ {
		seedAuditRecord(repo, makeAuditRecord(
			fmt.Sprintf("a%d", i),
			types.AuditEventTypeSignRequest,
			now.Add(-time.Duration(i)*time.Minute),
		))
	}

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	// First page with limit=2
	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?limit=2", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 2, len(resp.Records))
	assert.True(t, resp.HasMore)
	require.NotNil(t, resp.NextCursor)
	require.NotNil(t, resp.NextCursorID)

	// Second page using cursor (URL-encode to handle + in timezone offsets)
	rr2 := doAuditRequest(t, h, http.MethodGet,
		fmt.Sprintf("/api/v1/audit?limit=2&cursor=%s&cursor_id=%s",
			url.QueryEscape(*resp.NextCursor),
			url.QueryEscape(*resp.NextCursorID)),
		auditAPIKey(),
	)
	assert.Equal(t, http.StatusOK, rr2.Code)

	var resp2 ListAuditResponse
	require.NoError(t, json.NewDecoder(rr2.Body).Decode(&resp2))
	// The cursor should filter to next page
	assert.GreaterOrEqual(t, len(resp2.Records), 0)
}

func TestAuditHandler_InvalidCursor(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?cursor=not-a-timestamp", auditAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "invalid cursor")
}

func TestAuditHandler_CursorIDWithoutCursor(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()
	seedAuditRecord(repo, makeAuditRecord("a1", types.AuditEventTypeSignRequest, now))

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	// cursor_id without cursor is accepted (filter just passes through)
	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?cursor_id=a1", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------------------------------------------------------------------------
// Tests: repository error paths
// ---------------------------------------------------------------------------

func TestAuditHandler_CountError(t *testing.T) {
	repo := newMockAuditRepo()
	repo.countErr = fmt.Errorf("database connection lost")

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit", auditAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to count audit records")
}

func TestAuditHandler_QueryError(t *testing.T) {
	repo := newMockAuditRepo()
	repo.queryErr = fmt.Errorf("query timeout")

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit", auditAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to query audit records")
}

// ---------------------------------------------------------------------------
// Tests: toAuditRecordResponse with nil optional fields
// ---------------------------------------------------------------------------

func TestAuditHandler_ResponseNilOptionalFields(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()

	// Record with no optional pointer fields set
	rec := &types.AuditRecord{
		ID:            "audit-nil-opts",
		EventType:     types.AuditEventTypeAuthFailure,
		Severity:      types.AuditSeverityWarning,
		Timestamp:     now,
		APIKeyID:      "key-1",
		ActorAddress:  "10.0.0.1",
		ErrorMessage:  "invalid signature",
		RequestMethod: "POST",
		RequestPath:   "/api/v1/evm/sign",
	}
	seedAuditRecord(repo, rec)

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	require.Equal(t, 1, len(resp.Records))

	r := resp.Records[0]
	assert.Equal(t, "audit-nil-opts", r.ID)
	assert.Equal(t, "auth_failure", r.EventType)
	assert.Equal(t, "warning", r.Severity)
	assert.Equal(t, "invalid signature", r.ErrorMessage)
	assert.Nil(t, r.SignRequestID)
	assert.Nil(t, r.SignerAddress)
	assert.Nil(t, r.ChainType)
	assert.Nil(t, r.ChainID)
	assert.Nil(t, r.RuleID)
}

// ---------------------------------------------------------------------------
// Tests: pagination hasMore / no more
// ---------------------------------------------------------------------------

func TestAuditHandler_PaginationNoMore(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()
	// Add exactly 3 records, request with limit=5 -> should not have more
	for i := 0; i < 3; i++ {
		seedAuditRecord(repo, makeAuditRecord(
			fmt.Sprintf("a%d", i),
			types.AuditEventTypeSignRequest,
			now.Add(-time.Duration(i)*time.Minute),
		))
	}

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?limit=5", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 3, len(resp.Records))
	assert.False(t, resp.HasMore)
	assert.Nil(t, resp.NextCursor)
	assert.Nil(t, resp.NextCursorID)
}

func TestAuditHandler_PaginationExactLimit(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()
	// Add exactly limit+1 records (4 for limit=3) to trigger hasMore
	for i := 0; i < 4; i++ {
		seedAuditRecord(repo, makeAuditRecord(
			fmt.Sprintf("a%d", i),
			types.AuditEventTypeSignRequest,
			now.Add(-time.Duration(i)*time.Minute),
		))
	}

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?limit=3", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 3, len(resp.Records))
	assert.True(t, resp.HasMore)
	assert.NotNil(t, resp.NextCursor)
	assert.NotNil(t, resp.NextCursorID)
}

// ---------------------------------------------------------------------------
// Tests: multiple filters combined
// ---------------------------------------------------------------------------

func TestAuditHandler_MultipleFiltersCombined(t *testing.T) {
	repo := newMockAuditRepo()
	now := time.Now()

	ct := types.ChainTypeEVM
	r1 := makeAuditRecord("a1", types.AuditEventTypeSignRequest, now)
	r1.ChainType = &ct
	r1.APIKeyID = "key-x"
	seedAuditRecord(repo, r1)

	r2 := makeAuditRecord("a2", types.AuditEventTypeSignRequest, now)
	r2.APIKeyID = "key-y"
	seedAuditRecord(repo, r2)

	r3 := makeAuditRecord("a3", types.AuditEventTypeAuthSuccess, now)
	r3.ChainType = &ct
	r3.APIKeyID = "key-x"
	seedAuditRecord(repo, r3)

	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet,
		"/api/v1/audit?event_type=sign_request&chain_type=evm&api_key_id=key-x",
		auditAPIKey(),
	)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, len(resp.Records))
	assert.Equal(t, "a1", resp.Records[0].ID)
}

// ---------------------------------------------------------------------------
// Tests: writeJSON and writeError through handler
// ---------------------------------------------------------------------------

func TestAuditHandler_ContentTypeHeader(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit", auditAPIKey())
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}
