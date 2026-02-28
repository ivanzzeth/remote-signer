package views

import (
	"context"
	"errors"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
	"github.com/ivanzzeth/remote-signer/pkg/client/mock"
)

func newTestAuditModel(t *testing.T) (*AuditModel, *mock.AuditService, *mock.RequestService) {
	t.Helper()
	auditSvc := mock.NewAuditService()
	requestsSvc := mock.NewRequestService()
	model, err := newAuditModelFromServices(auditSvc, requestsSvc, context.Background())
	require.NoError(t, err)
	return model, auditSvc, requestsSvc
}

func TestNewAuditModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewAuditModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		auditSvc := mock.NewAuditService()
		requestsSvc := mock.NewRequestService()
		_, err := newAuditModelFromServices(auditSvc, requestsSvc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		require.NotNil(t, model)
		assert.True(t, model.loading)
		assert.Equal(t, 30, model.limit)
	})
}

func TestAuditModel_Update(t *testing.T) {
	t.Run("handles audit data message", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)

		records := []audit.Record{
			{ID: "audit-1", EventType: "sign_request", Severity: "info", Timestamp: time.Now()},
			{ID: "audit-2", EventType: "sign_complete", Severity: "info", Timestamp: time.Now()},
		}

		msg := AuditDataMsg{
			Records: records,
			Total:   2,
			HasMore: false,
			Err:     nil,
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*AuditModel)

		assert.False(t, m.loading)
		assert.Nil(t, m.err)
		assert.Len(t, m.records, 2)
		assert.Equal(t, 2, m.total)
	})

	t.Run("handles audit data error", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)

		msg := AuditDataMsg{Err: errors.New("fetch failed")}
		newModel, _ := model.Update(msg)
		m := newModel.(*AuditModel)

		assert.False(t, m.loading)
		assert.NotNil(t, m.err)
	})

	t.Run("handles navigation keys", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false
		model.records = []audit.Record{
			{ID: "audit-1"},
			{ID: "audit-2"},
			{ID: "audit-3"},
		}

		// Test down
		model.selectedIdx = 0
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m := newModel.(*AuditModel)
		assert.Equal(t, 1, m.selectedIdx)

		// Test up
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*AuditModel)
		assert.Equal(t, 0, m.selectedIdx)
	})

	t.Run("handles filter by event type", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false

		// Press 'e' to filter by event type
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
		m := newModel.(*AuditModel)
		assert.True(t, m.showFilter)
		assert.Equal(t, "event", m.filterType)
	})

	t.Run("handles filter by severity", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false

		// Press 's' to filter by severity
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
		m := newModel.(*AuditModel)
		assert.True(t, m.showFilter)
		assert.Equal(t, "severity", m.filterType)
	})

	t.Run("handles view detail", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false
		model.records = []audit.Record{
			{ID: "audit-1", EventType: "sign_request"},
		}
		model.selectedIdx = 0

		// Press Enter to view detail
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*AuditModel)
		assert.True(t, m.showDetail)

		// Press Esc to go back
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m = newModel.(*AuditModel)
		assert.False(t, m.showDetail)
	})

	t.Run("handles pagination - next page", func(t *testing.T) {
		model, auditSvc, _ := newTestAuditModel(t)
		auditSvc.ListFunc = func(ctx context.Context, filter *audit.ListFilter) (*audit.ListResponse, error) {
			return &audit.ListResponse{}, nil
		}

		model.loading = false
		model.hasMore = true
		nextCursor := "next-cursor"
		model.nextCursor = &nextCursor

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
		m := newModel.(*AuditModel)

		assert.NotNil(t, m.cursor)
		assert.Equal(t, "next-cursor", *m.cursor)
		assert.NotNil(t, cmd)
	})

	t.Run("handles pagination - previous page", func(t *testing.T) {
		model, auditSvc, _ := newTestAuditModel(t)
		auditSvc.ListFunc = func(ctx context.Context, filter *audit.ListFilter) (*audit.ListResponse, error) {
			return &audit.ListResponse{}, nil
		}

		model.loading = false
		prevCursor := "prev-cursor"
		model.cursorHistory = []auditCursorState{
			{cursor: &prevCursor},
		}

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
		m := newModel.(*AuditModel)

		assert.Len(t, m.cursorHistory, 0)
		assert.NotNil(t, cmd)
	})

	t.Run("handles clear filters", func(t *testing.T) {
		model, auditSvc, _ := newTestAuditModel(t)
		auditSvc.ListFunc = func(ctx context.Context, filter *audit.ListFilter) (*audit.ListResponse, error) {
			return &audit.ListResponse{}, nil
		}

		model.loading = false
		model.eventFilter = "sign_request"
		model.severityFilter = "critical"

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})
		m := newModel.(*AuditModel)

		assert.Equal(t, "", m.eventFilter)
		assert.Equal(t, "", m.severityFilter)
	})
}

func TestAuditModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = true
		model.width = 150
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 150
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders audit list", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.records = []audit.Record{
			{ID: "audit-1", EventType: "sign_request", Severity: "info", Timestamp: time.Now()},
		}
		model.total = 1

		view := model.View()
		assert.Contains(t, view, "Audit Logs")
		assert.Contains(t, view, "sign_request")
	})

	t.Run("renders empty list", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.records = []audit.Record{}

		view := model.View()
		assert.Contains(t, view, "No audit records found")
	})

	t.Run("renders detail view", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false
		model.showDetail = true
		model.width = 150
		model.height = 30
		model.records = []audit.Record{
			{ID: "audit-1", EventType: "sign_request", Severity: "info", Timestamp: time.Now(), APIKeyID: "key-1"},
		}
		model.selectedIdx = 0

		view := model.View()
		assert.Contains(t, view, "Audit Record Details")
	})

	t.Run("renders with filters", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.eventFilter = "sign_request"
		model.severityFilter = "critical"
		model.records = []audit.Record{}

		view := model.View()
		assert.Contains(t, view, "filtered")
	})
}

func TestAuditModel_LoadData(t *testing.T) {
	t.Run("calls client with correct filter", func(t *testing.T) {
		model, auditSvc, _ := newTestAuditModel(t)
		var capturedFilter *audit.ListFilter
		auditSvc.ListFunc = func(ctx context.Context, filter *audit.ListFilter) (*audit.ListResponse, error) {
			capturedFilter = filter
			return &audit.ListResponse{Records: []audit.Record{}, Total: 0}, nil
		}

		model.eventFilter = "sign_request"
		model.severityFilter = "info"
		model.limit = 30

		cmd := model.loadData()
		msg := cmd()

		require.NotNil(t, capturedFilter)
		assert.Equal(t, "sign_request", capturedFilter.EventType)
		assert.Equal(t, "info", capturedFilter.Severity)
		assert.Equal(t, 30, capturedFilter.Limit)

		dataMsg, ok := msg.(AuditDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
	})
}

func TestAuditModel_ResetPagination(t *testing.T) {
	t.Run("resets all pagination state", func(t *testing.T) {
		model, _, _ := newTestAuditModel(t)

		cursor := "test-cursor"
		model.cursor = &cursor
		model.nextCursor = &cursor
		model.cursorHistory = []auditCursorState{{cursor: &cursor}}
		model.selectedIdx = 5
		model.hasMore = true

		model.resetPagination()

		assert.Nil(t, model.cursor)
		assert.Nil(t, model.cursorID)
		assert.Nil(t, model.nextCursor)
		assert.Nil(t, model.nextCursorID)
		assert.Nil(t, model.cursorHistory)
		assert.Equal(t, 0, model.selectedIdx)
		assert.False(t, model.hasMore)
	})
}
