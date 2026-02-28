package views

import (
	"context"
	"errors"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/mock"
)

func newTestRuleDetailModel(t *testing.T) (*RuleDetailModel, *mock.RuleService) {
	t.Helper()
	svc := mock.NewRuleService()
	model, err := newRuleDetailModelFromService(svc, context.Background())
	require.NoError(t, err)
	return model, svc
}

func TestNewRuleDetailModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewRuleDetailModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		svc := mock.NewRuleService()
		_, err := newRuleDetailModelFromService(svc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		require.NotNil(t, model)
	})
}

func TestRuleDetailModel_Update(t *testing.T) {
	t.Run("handles rule detail data message", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)

		rule := &evm.Rule{
			ID:        "rule-123",
			Name:      "Test Rule",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		msg := RuleDetailDataMsg{Rule: rule, Err: nil}
		newModel, _ := model.Update(msg)
		m := newModel.(*RuleDetailModel)

		assert.False(t, m.loading)
		assert.Nil(t, m.err)
		assert.NotNil(t, m.rule)
		assert.Equal(t, "rule-123", m.rule.ID)
	})

	t.Run("handles rule detail data error", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)

		msg := RuleDetailDataMsg{Err: errors.New("rule not found")}
		newModel, _ := model.Update(msg)
		m := newModel.(*RuleDetailModel)

		assert.False(t, m.loading)
		assert.NotNil(t, m.err)
	})

	t.Run("handles rule action success - toggle", func(t *testing.T) {
		model, svc := newTestRuleDetailModel(t)
		svc.GetFunc = func(ctx context.Context, ruleID string) (*evm.Rule, error) {
			return &evm.Rule{ID: ruleID, Enabled: true}, nil
		}

		model.rule = &evm.Rule{ID: "rule-123", Enabled: false}

		msg := RuleDetailActionMsg{Action: "toggle", Success: true, Message: "Rule enabled", Err: nil}
		newModel, cmd := model.Update(msg)
		m := newModel.(*RuleDetailModel)

		assert.False(t, m.loading)
		assert.Contains(t, m.actionResult, "Rule enabled")
		assert.NotNil(t, cmd) // Reload command
	})

	t.Run("handles rule action success - delete", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.rule = &evm.Rule{ID: "rule-123"}

		msg := RuleDetailActionMsg{Action: "delete", Success: true, Message: "Rule deleted", Err: nil}
		newModel, _ := model.Update(msg)
		m := newModel.(*RuleDetailModel)

		assert.False(t, m.loading)
		assert.Contains(t, m.actionResult, "Rule deleted")
		assert.True(t, m.goBack) // Should go back after delete
	})

	t.Run("handles rule action error", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)

		msg := RuleDetailActionMsg{Action: "toggle", Success: false, Err: errors.New("permission denied")}
		newModel, _ := model.Update(msg)
		m := newModel.(*RuleDetailModel)

		assert.Contains(t, m.actionResult, "Error")
	})

	t.Run("handles toggle key", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.rule = &evm.Rule{ID: "rule-123", Enabled: true}

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
		m := newModel.(*RuleDetailModel)

		assert.True(t, m.showToggle)
	})

	t.Run("handles delete key", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.rule = &evm.Rule{ID: "rule-123"}

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
		m := newModel.(*RuleDetailModel)

		assert.True(t, m.showDelete)
	})

	t.Run("handles back navigation", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m := newModel.(*RuleDetailModel)

		assert.True(t, m.goBack)
	})

	t.Run("handles toggle dialog - confirm", func(t *testing.T) {
		model, svc := newTestRuleDetailModel(t)
		svc.ToggleFunc = func(ctx context.Context, ruleID string, enabled bool) (*evm.Rule, error) {
			return &evm.Rule{ID: ruleID, Enabled: enabled}, nil
		}

		model.showToggle = true
		model.rule = &evm.Rule{ID: "rule-123", Enabled: false}

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
		m := newModel.(*RuleDetailModel)

		assert.True(t, m.loading)
		assert.False(t, m.showToggle)
		assert.NotNil(t, cmd)
	})

	t.Run("handles toggle dialog - cancel", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.showToggle = true

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
		m := newModel.(*RuleDetailModel)

		assert.False(t, m.showToggle)
	})

	t.Run("handles delete dialog - confirm", func(t *testing.T) {
		model, svc := newTestRuleDetailModel(t)
		svc.DeleteFunc = func(ctx context.Context, ruleID string) error {
			return nil
		}

		model.showDelete = true
		model.rule = &evm.Rule{ID: "rule-123"}

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
		m := newModel.(*RuleDetailModel)

		assert.True(t, m.loading)
		assert.False(t, m.showDelete)
		assert.NotNil(t, cmd)
	})

	t.Run("handles delete dialog - cancel", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.showDelete = true

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
		m := newModel.(*RuleDetailModel)

		assert.False(t, m.showDelete)
	})

	t.Run("handles refresh key", func(t *testing.T) {
		model, svc := newTestRuleDetailModel(t)
		svc.GetFunc = func(ctx context.Context, ruleID string) (*evm.Rule, error) {
			return &evm.Rule{ID: ruleID}, nil
		}

		model.rule = &evm.Rule{ID: "rule-123"}

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
		m := newModel.(*RuleDetailModel)

		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})
}

func TestRuleDetailModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.loading = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders rule details", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.loading = false
		model.width = 100
		model.height = 30
		model.SetSize(100, 30)
		model.rule = &evm.Rule{
			ID:        "rule-123",
			Name:      "Test Rule",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		view := model.View()
		assert.Contains(t, view, "Rule Details")
		assert.Contains(t, view, "rule-123")
		assert.Contains(t, view, "Test Rule")
	})

	t.Run("renders delete confirmation", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.loading = false
		model.showDelete = true
		model.width = 100
		model.height = 30
		model.rule = &evm.Rule{
			ID:   "rule-123",
			Name: "Test Rule",
			Type: "evm_address_list",
		}

		view := model.View()
		assert.Contains(t, view, "Delete Rule")
		assert.Contains(t, view, "Are you sure")
	})

	t.Run("renders toggle confirmation", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.loading = false
		model.showToggle = true
		model.width = 100
		model.height = 30
		model.rule = &evm.Rule{
			ID:      "rule-123",
			Name:    "Test Rule",
			Enabled: true,
		}

		view := model.View()
		assert.Contains(t, view, "Disable Rule")
	})

	t.Run("renders enable confirmation for disabled rule", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.loading = false
		model.showToggle = true
		model.width = 100
		model.height = 30
		model.rule = &evm.Rule{
			ID:      "rule-123",
			Name:    "Test Rule",
			Enabled: false,
		}

		view := model.View()
		assert.Contains(t, view, "Enable Rule")
	})

	t.Run("renders no rule loaded", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)
		model.loading = false
		model.rule = nil
		model.width = 100
		model.height = 30
		model.SetSize(100, 30)

		view := model.View()
		assert.Contains(t, view, "No rule loaded")
	})
}

func TestRuleDetailModel_LoadRule(t *testing.T) {
	t.Run("sets loading state and resets fields", func(t *testing.T) {
		model, svc := newTestRuleDetailModel(t)
		svc.GetFunc = func(ctx context.Context, ruleID string) (*evm.Rule, error) {
			return &evm.Rule{ID: ruleID}, nil
		}

		model.showDelete = true
		model.showToggle = true
		model.actionResult = "some result"

		cmd := model.LoadRule("rule-123")
		assert.True(t, model.loading)
		assert.False(t, model.showDelete)
		assert.False(t, model.showToggle)
		assert.Equal(t, "", model.actionResult)
		assert.NotNil(t, cmd)
	})
}

func TestRuleDetailModel_ShouldGoBack(t *testing.T) {
	t.Run("returns goBack flag", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)

		assert.False(t, model.ShouldGoBack())

		model.goBack = true
		assert.True(t, model.ShouldGoBack())
	})
}

func TestRuleDetailModel_ResetGoBack(t *testing.T) {
	t.Run("resets goBack flag", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)

		model.goBack = true
		model.ResetGoBack()
		assert.False(t, model.goBack)
	})
}

func TestRuleDetailModel_SetSize(t *testing.T) {
	t.Run("sets width and height", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)

		model.SetSize(120, 40)
		assert.Equal(t, 120, model.width)
		assert.Equal(t, 40, model.height)
		assert.True(t, model.ready)
	})

	t.Run("updates viewport on resize", func(t *testing.T) {
		model, _ := newTestRuleDetailModel(t)

		model.SetSize(100, 30)
		assert.True(t, model.ready)

		// Resize
		model.SetSize(150, 50)
		assert.Equal(t, 150, model.width)
		assert.Equal(t, 50, model.height)
	})
}
