package views

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/mock"
)

func newTestRulesModel(t *testing.T) (*RulesModel, *mock.RuleService) {
	t.Helper()
	svc := mock.NewRuleService()
	model, err := newRulesModelFromService(svc, context.Background())
	require.NoError(t, err)
	return model, svc
}

func TestNewRulesModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewRulesModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		svc := mock.NewRuleService()
		_, err := newRulesModelFromService(svc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		require.NotNil(t, model)
		assert.True(t, model.loading)
		assert.Equal(t, 20, model.limit)
	})
}

func TestRulesModel_Update(t *testing.T) {
	t.Run("handles rules data message", func(t *testing.T) {
		model, _ := newTestRulesModel(t)

		rules := []evm.Rule{
			{ID: "rule-1", Name: "Test Rule 1", Type: "evm_address_list", Mode: "whitelist", Enabled: true},
			{ID: "rule-2", Name: "Test Rule 2", Type: "evm_value_limit", Mode: "blocklist", Enabled: false},
		}

		msg := RulesDataMsg{Rules: rules, Total: 2, Err: nil}
		newModel, _ := model.Update(msg)
		m := newModel.(*RulesModel)

		assert.False(t, m.loading)
		assert.Nil(t, m.err)
		assert.Len(t, m.rules, 2)
		assert.Equal(t, 2, m.total)
	})

	t.Run("handles rules data error", func(t *testing.T) {
		model, _ := newTestRulesModel(t)

		msg := RulesDataMsg{Err: errors.New("fetch failed")}
		newModel, _ := model.Update(msg)
		m := newModel.(*RulesModel)

		assert.False(t, m.loading)
		assert.NotNil(t, m.err)
	})

	t.Run("handles rule action message success", func(t *testing.T) {
		model, svc := newTestRulesModel(t)
		svc.ListFunc = func(ctx context.Context, filter *evm.ListRulesFilter) (*evm.ListRulesResponse, error) {
			return &evm.ListRulesResponse{}, nil
		}

		msg := RuleActionMsg{Action: "toggle", Success: true, Message: "Rule enabled"}
		newModel, cmd := model.Update(msg)
		m := newModel.(*RulesModel)

		// After success, Refresh() is called which sets loading to true
		assert.True(t, m.loading)
		assert.Contains(t, m.actionResult, "Rule enabled")
		assert.NotNil(t, cmd) // Refresh command
	})

	t.Run("handles rule action message error", func(t *testing.T) {
		model, _ := newTestRulesModel(t)

		msg := RuleActionMsg{Action: "delete", Success: false, Err: errors.New("permission denied")}
		newModel, _ := model.Update(msg)
		m := newModel.(*RulesModel)

		assert.Contains(t, m.actionResult, "Error")
	})

	t.Run("handles navigation keys", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = false
		model.rules = []evm.Rule{
			{ID: "rule-1"},
			{ID: "rule-2"},
			{ID: "rule-3"},
		}

		// Test down
		model.selectedIdx = 0
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m := newModel.(*RulesModel)
		assert.Equal(t, 1, m.selectedIdx)

		// Test up
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*RulesModel)
		assert.Equal(t, 0, m.selectedIdx)
	})

	t.Run("handles toggle rule", func(t *testing.T) {
		model, svc := newTestRulesModel(t)
		svc.ToggleFunc = func(ctx context.Context, ruleID string, enabled bool) (*evm.Rule, error) {
			return &evm.Rule{ID: ruleID, Enabled: enabled}, nil
		}

		model.loading = false
		model.rules = []evm.Rule{
			{ID: "rule-1", Enabled: false},
		}
		model.selectedIdx = 0

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
		m := newModel.(*RulesModel)

		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})

	t.Run("handles delete confirmation", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = false
		model.rules = []evm.Rule{
			{ID: "rule-1"},
		}
		model.selectedIdx = 0

		// Press 'd' to show delete confirmation
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
		m := newModel.(*RulesModel)
		assert.True(t, m.showDelete)

		// Press 'n' to cancel
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
		m = newModel.(*RulesModel)
		assert.False(t, m.showDelete)
	})

	t.Run("handles filter by type", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = false

		// Press 'f' to filter by type
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
		m := newModel.(*RulesModel)
		assert.True(t, m.showFilter)
		assert.Equal(t, "type", m.filterType)
	})

	t.Run("handles filter by mode", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = false

		// Press 'm' to filter by mode
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("m")})
		m := newModel.(*RulesModel)
		assert.True(t, m.showFilter)
		assert.Equal(t, "mode", m.filterType)
	})
}

func TestRulesModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = true
		model.width = 150
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 150
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders rules list", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.rules = []evm.Rule{
			{ID: "rule-123", Name: "Test Rule", Type: "evm_address_list", Mode: "whitelist", Enabled: true},
		}
		model.total = 1

		view := model.View()
		assert.Contains(t, view, "Authorization Rules")
		assert.Contains(t, view, "Test Rule")
	})

	t.Run("renders empty list", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.rules = []evm.Rule{}

		view := model.View()
		assert.Contains(t, view, "No rules found")
	})

	t.Run("renders delete confirmation", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.loading = false
		model.showDelete = true
		model.width = 150
		model.height = 30
		model.rules = []evm.Rule{
			{ID: "rule-1", Name: "Test Rule"},
		}

		view := model.View()
		assert.Contains(t, view, "Delete Rule")
		assert.Contains(t, view, "Are you sure")
	})
}

func TestRulesModel_GetSelectedRuleID(t *testing.T) {
	t.Run("returns empty when no rules", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.rules = []evm.Rule{}

		id := model.GetSelectedRuleID()
		assert.Equal(t, "", id)
	})

	t.Run("returns selected rule ID", func(t *testing.T) {
		model, _ := newTestRulesModel(t)
		model.rules = []evm.Rule{
			{ID: "rule-1"},
			{ID: "rule-2"},
		}
		model.selectedIdx = 1

		id := model.GetSelectedRuleID()
		assert.Equal(t, "rule-2", id)
	})
}

func TestRulesModel_LoadData(t *testing.T) {
	t.Run("calls client with correct filter", func(t *testing.T) {
		model, svc := newTestRulesModel(t)
		var capturedFilter *evm.ListRulesFilter
		svc.ListFunc = func(ctx context.Context, filter *evm.ListRulesFilter) (*evm.ListRulesResponse, error) {
			capturedFilter = filter
			return &evm.ListRulesResponse{Rules: []evm.Rule{}, Total: 0}, nil
		}

		model.typeFilter = "evm_address_list"
		model.modeFilter = "whitelist"
		model.offset = 10
		model.limit = 20

		cmd := model.loadData()
		msg := cmd()

		require.NotNil(t, capturedFilter)
		assert.Equal(t, "evm_address_list", capturedFilter.Type)
		assert.Equal(t, "whitelist", capturedFilter.Mode)
		assert.Equal(t, 10, capturedFilter.Offset)
		assert.Equal(t, 20, capturedFilter.Limit)

		dataMsg, ok := msg.(RulesDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
	})
}
