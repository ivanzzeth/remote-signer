package views

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

func TestNewDashboardModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewDashboardModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		mockClient := client.NewMockClient()
		_, err := NewDashboardModel(mockClient, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)
		require.NotNil(t, model)
		assert.True(t, model.loading)
	})
}

func TestDashboardModel_Update(t *testing.T) {
	t.Run("handles dashboard data message success", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)

		data := &DashboardData{
			Health: &client.HealthResponse{
				Status:  "healthy",
				Version: "1.0.0",
			},
			RequestCounts: map[string]int{
				"pending":   5,
				"completed": 10,
			},
			TotalRequests: 15,
			TotalRules:    3,
		}

		msg := DashboardDataMsg{Data: data, Err: nil}
		newModel, _ := model.Update(msg)
		m := newModel.(*DashboardModel)

		assert.False(t, m.loading)
		assert.True(t, m.connected)
		assert.Nil(t, m.err)
		assert.NotNil(t, m.data)
		assert.Equal(t, "healthy", m.data.Health.Status)
		assert.Equal(t, 15, m.data.TotalRequests)
	})

	t.Run("handles dashboard data message error", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)

		msg := DashboardDataMsg{Data: nil, Err: errors.New("connection failed")}
		newModel, _ := model.Update(msg)
		m := newModel.(*DashboardModel)

		assert.False(t, m.loading)
		assert.False(t, m.connected)
		assert.NotNil(t, m.err)
	})

	t.Run("handles refresh key", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.HealthFunc = func(ctx context.Context) (*client.HealthResponse, error) {
			return &client.HealthResponse{Status: "healthy"}, nil
		}
		mockClient.ListRequestsFunc = func(ctx context.Context, filter *client.ListRequestsFilter) (*client.ListRequestsResponse, error) {
			return &client.ListRequestsResponse{}, nil
		}
		mockClient.ListRulesFunc = func(ctx context.Context, filter *client.ListRulesFilter) (*client.ListRulesResponse, error) {
			return &client.ListRulesResponse{}, nil
		}

		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
		m := newModel.(*DashboardModel)

		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})
}

func TestDashboardModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders dashboard with data", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.connected = true
		model.width = 100
		model.height = 30
		model.data = &DashboardData{
			Health: &client.HealthResponse{
				Status:  "healthy",
				Version: "1.0.0",
			},
			RequestCounts: map[string]int{
				"pending":   5,
				"completed": 10,
			},
			TotalRequests: 15,
			TotalRules:    3,
		}

		view := model.View()
		assert.Contains(t, view, "Service Status")
		assert.Contains(t, view, "Connected")
	})
}

func TestDashboardModel_LoadData(t *testing.T) {
	t.Run("loads health and counts", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.HealthFunc = func(ctx context.Context) (*client.HealthResponse, error) {
			return &client.HealthResponse{Status: "healthy", Version: "1.0.0"}, nil
		}
		mockClient.ListRequestsFunc = func(ctx context.Context, filter *client.ListRequestsFilter) (*client.ListRequestsResponse, error) {
			return &client.ListRequestsResponse{Total: 5}, nil
		}
		mockClient.ListRulesFunc = func(ctx context.Context, filter *client.ListRulesFilter) (*client.ListRulesResponse, error) {
			return &client.ListRulesResponse{Total: 3}, nil
		}

		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)

		cmd := model.loadData()
		msg := cmd()

		dataMsg, ok := msg.(DashboardDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
		assert.NotNil(t, dataMsg.Data)
		assert.Equal(t, "healthy", dataMsg.Data.Health.Status)
	})

	t.Run("returns error on health check failure", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.HealthFunc = func(ctx context.Context) (*client.HealthResponse, error) {
			return nil, errors.New("connection refused")
		}

		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)

		cmd := model.loadData()
		msg := cmd()

		dataMsg, ok := msg.(DashboardDataMsg)
		require.True(t, ok)
		assert.NotNil(t, dataMsg.Err)
		assert.Contains(t, dataMsg.Err.Error(), "health check failed")
	})
}

func TestDashboardModel_SetSize(t *testing.T) {
	t.Run("sets width and height", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)

		model.SetSize(120, 40)
		assert.Equal(t, 120, model.width)
		assert.Equal(t, 40, model.height)
	})
}

func TestDashboardModel_Refresh(t *testing.T) {
	t.Run("sets loading and returns command", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.HealthFunc = func(ctx context.Context) (*client.HealthResponse, error) {
			return &client.HealthResponse{}, nil
		}
		mockClient.ListRequestsFunc = func(ctx context.Context, filter *client.ListRequestsFilter) (*client.ListRequestsResponse, error) {
			return &client.ListRequestsResponse{}, nil
		}
		mockClient.ListRulesFunc = func(ctx context.Context, filter *client.ListRulesFilter) (*client.ListRulesResponse, error) {
			return &client.ListRulesResponse{}, nil
		}

		model, err := NewDashboardModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false

		cmd := model.Refresh()
		assert.True(t, model.loading)
		assert.NotNil(t, cmd)
	})
}
