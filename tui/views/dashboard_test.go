package views

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/mock"
)

// mockHealthChecker implements the healthChecker interface for testing.
type mockHealthChecker struct {
	HealthFunc func(ctx context.Context) (*client.HealthResponse, error)
}

func (m *mockHealthChecker) Health(ctx context.Context) (*client.HealthResponse, error) {
	if m.HealthFunc != nil {
		return m.HealthFunc(ctx)
	}
	return &client.HealthResponse{}, nil
}

func newTestDashboardModel(t *testing.T) (*DashboardModel, *mockHealthChecker, *mock.RequestService, *mock.RuleService) {
	t.Helper()
	health := &mockHealthChecker{}
	requests := mock.NewRequestService()
	rules := mock.NewRuleService()
	model, err := newDashboardModelFromServices(health, requests, rules, context.Background())
	require.NoError(t, err)
	return model, health, requests, rules
}

func TestNewDashboardModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewDashboardModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		health := &mockHealthChecker{}
		requests := mock.NewRequestService()
		rules := mock.NewRuleService()
		_, err := newDashboardModelFromServices(health, requests, rules, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, _, _, _ := newTestDashboardModel(t)
		require.NotNil(t, model)
		assert.True(t, model.loading)
	})
}

func TestDashboardModel_Update(t *testing.T) {
	t.Run("handles dashboard data message success", func(t *testing.T) {
		model, _, _, _ := newTestDashboardModel(t)

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
		model, _, _, _ := newTestDashboardModel(t)

		msg := DashboardDataMsg{Data: nil, Err: errors.New("connection failed")}
		newModel, _ := model.Update(msg)
		m := newModel.(*DashboardModel)

		assert.False(t, m.loading)
		assert.False(t, m.connected)
		assert.NotNil(t, m.err)
	})

	t.Run("handles refresh key", func(t *testing.T) {
		model, health, requests, rules := newTestDashboardModel(t)
		health.HealthFunc = func(ctx context.Context) (*client.HealthResponse, error) {
			return &client.HealthResponse{Status: "healthy"}, nil
		}
		requests.ListFunc = func(ctx context.Context, filter *evm.ListRequestsFilter) (*evm.ListRequestsResponse, error) {
			return &evm.ListRequestsResponse{}, nil
		}
		rules.ListFunc = func(ctx context.Context, filter *evm.ListRulesFilter) (*evm.ListRulesResponse, error) {
			return &evm.ListRulesResponse{}, nil
		}

		model.loading = false

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
		m := newModel.(*DashboardModel)

		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})
}

func TestDashboardModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		model, _, _, _ := newTestDashboardModel(t)
		model.loading = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		model, _, _, _ := newTestDashboardModel(t)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders dashboard with data", func(t *testing.T) {
		model, _, _, _ := newTestDashboardModel(t)
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
		model, health, requests, rules := newTestDashboardModel(t)
		health.HealthFunc = func(ctx context.Context) (*client.HealthResponse, error) {
			return &client.HealthResponse{Status: "healthy", Version: "1.0.0"}, nil
		}
		requests.ListFunc = func(ctx context.Context, filter *evm.ListRequestsFilter) (*evm.ListRequestsResponse, error) {
			return &evm.ListRequestsResponse{Total: 5}, nil
		}
		rules.ListFunc = func(ctx context.Context, filter *evm.ListRulesFilter) (*evm.ListRulesResponse, error) {
			return &evm.ListRulesResponse{Total: 3}, nil
		}

		cmd := model.loadData()
		msg := cmd()

		dataMsg, ok := msg.(DashboardDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
		assert.NotNil(t, dataMsg.Data)
		assert.Equal(t, "healthy", dataMsg.Data.Health.Status)
	})

	t.Run("returns error on health check failure", func(t *testing.T) {
		model, health, _, _ := newTestDashboardModel(t)
		health.HealthFunc = func(ctx context.Context) (*client.HealthResponse, error) {
			return nil, errors.New("connection refused")
		}

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
		model, _, _, _ := newTestDashboardModel(t)

		model.SetSize(120, 40)
		assert.Equal(t, 120, model.width)
		assert.Equal(t, 40, model.height)
	})
}

func TestDashboardModel_Refresh(t *testing.T) {
	t.Run("sets loading and returns command", func(t *testing.T) {
		model, health, requests, rules := newTestDashboardModel(t)
		health.HealthFunc = func(ctx context.Context) (*client.HealthResponse, error) {
			return &client.HealthResponse{}, nil
		}
		requests.ListFunc = func(ctx context.Context, filter *evm.ListRequestsFilter) (*evm.ListRequestsResponse, error) {
			return &evm.ListRequestsResponse{}, nil
		}
		rules.ListFunc = func(ctx context.Context, filter *evm.ListRulesFilter) (*evm.ListRulesResponse, error) {
			return &evm.ListRulesResponse{}, nil
		}

		model.loading = false

		cmd := model.Refresh()
		assert.True(t, model.loading)
		assert.NotNil(t, cmd)
	})
}
