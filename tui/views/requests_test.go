package views

import (
	"context"
	"errors"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

func TestNewRequestsModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewRequestsModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		mockClient := client.NewMockClient()
		_, err := NewRequestsModel(mockClient, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		require.NotNil(t, model)
		assert.True(t, model.loading)
		assert.Equal(t, 20, model.limit)
	})
}

func TestRequestsModel_Update(t *testing.T) {
	t.Run("handles requests data message", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)

		requests := []client.RequestStatus{
			{ID: "req-1", Status: "pending", SignerAddress: "0x1234", CreatedAt: time.Now()},
			{ID: "req-2", Status: "completed", SignerAddress: "0x5678", CreatedAt: time.Now()},
		}

		msg := RequestsDataMsg{
			Requests: requests,
			Total:    2,
			HasMore:  false,
			Err:      nil,
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*RequestsModel)

		assert.False(t, m.loading)
		assert.Nil(t, m.err)
		assert.Len(t, m.requests, 2)
		assert.Equal(t, 2, m.total)
	})

	t.Run("handles requests data error", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)

		msg := RequestsDataMsg{Err: errors.New("fetch failed")}
		newModel, _ := model.Update(msg)
		m := newModel.(*RequestsModel)

		assert.False(t, m.loading)
		assert.NotNil(t, m.err)
	})

	t.Run("handles navigation keys", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.requests = []client.RequestStatus{
			{ID: "req-1"},
			{ID: "req-2"},
			{ID: "req-3"},
		}

		// Test down
		model.selectedIdx = 0
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m := newModel.(*RequestsModel)
		assert.Equal(t, 1, m.selectedIdx)

		// Test up
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*RequestsModel)
		assert.Equal(t, 0, m.selectedIdx)
	})

	t.Run("handles filter mode", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false

		// Enter filter mode
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
		m := newModel.(*RequestsModel)
		assert.True(t, m.showFilter)

		// Exit filter mode
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m = newModel.(*RequestsModel)
		assert.False(t, m.showFilter)
	})

	t.Run("handles clear filter", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.ListRequestsFunc = func(ctx context.Context, filter *client.ListRequestsFilter) (*client.ListRequestsResponse, error) {
			return &client.ListRequestsResponse{}, nil
		}

		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.statusFilter = "pending"

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})
		m := newModel.(*RequestsModel)
		assert.Equal(t, "", m.statusFilter)
	})

	t.Run("handles pagination - next page", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.ListRequestsFunc = func(ctx context.Context, filter *client.ListRequestsFilter) (*client.ListRequestsResponse, error) {
			return &client.ListRequestsResponse{}, nil
		}

		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.hasMore = true
		nextCursor := "next-cursor"
		model.nextCursor = &nextCursor

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
		m := newModel.(*RequestsModel)

		assert.NotNil(t, m.cursor)
		assert.Equal(t, "next-cursor", *m.cursor)
		assert.NotNil(t, cmd)
	})
}

func TestRequestsModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = true
		model.width = 150
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 150
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders requests list", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.width = 150
		model.height = 30
		model.requests = []client.RequestStatus{
			{ID: "req-123", Status: "pending", SignerAddress: "0x1234", SignType: "personal", CreatedAt: time.Now()},
		}
		model.total = 1

		view := model.View()
		assert.Contains(t, view, "Sign Requests")
		assert.Contains(t, view, "req-123")
	})

	t.Run("renders empty list", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.width = 150
		model.height = 30
		model.requests = []client.RequestStatus{}

		view := model.View()
		assert.Contains(t, view, "No requests found")
	})

	t.Run("renders filter input", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.showFilter = true
		model.width = 150
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Filter")
	})
}

func TestRequestsModel_GetSelectedRequestID(t *testing.T) {
	t.Run("returns empty when no requests", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.requests = []client.RequestStatus{}

		id := model.GetSelectedRequestID()
		assert.Equal(t, "", id)
	})

	t.Run("returns selected request ID", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.requests = []client.RequestStatus{
			{ID: "req-1"},
			{ID: "req-2"},
		}
		model.selectedIdx = 1

		id := model.GetSelectedRequestID()
		assert.Equal(t, "req-2", id)
	})
}

func TestRequestsModel_LoadData(t *testing.T) {
	t.Run("calls client with correct filter", func(t *testing.T) {
		mockClient := client.NewMockClient()
		var capturedFilter *client.ListRequestsFilter
		mockClient.ListRequestsFunc = func(ctx context.Context, filter *client.ListRequestsFilter) (*client.ListRequestsResponse, error) {
			capturedFilter = filter
			return &client.ListRequestsResponse{
				Requests: []client.RequestStatus{},
				Total:    0,
			}, nil
		}

		model, err := NewRequestsModel(mockClient, context.Background())
		require.NoError(t, err)
		model.statusFilter = "pending"
		model.limit = 20

		cmd := model.loadData()
		msg := cmd()

		require.NotNil(t, capturedFilter)
		assert.Equal(t, "pending", capturedFilter.Status)
		assert.Equal(t, 20, capturedFilter.Limit)

		dataMsg, ok := msg.(RequestsDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
	})
}
