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

func newTestRequestDetailModel(t *testing.T) (*RequestDetailModel, *mock.RequestService) {
	t.Helper()
	svc := mock.NewRequestService()
	model, err := newRequestDetailModelFromService(svc, context.Background())
	require.NoError(t, err)
	return model, svc
}

func TestNewRequestDetailModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewRequestDetailModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		svc := mock.NewRequestService()
		_, err := newRequestDetailModelFromService(svc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		require.NotNil(t, model)
	})
}

func TestRequestDetailModel_Update(t *testing.T) {
	t.Run("handles request detail data message", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)

		request := &evm.RequestStatus{
			ID:            "req-123",
			Status:        "pending",
			SignerAddress: "0x1234",
			SignType:      "personal",
			CreatedAt:     time.Now(),
		}

		msg := RequestDetailDataMsg{Request: request, Err: nil}
		newModel, _ := model.Update(msg)
		m := newModel.(*RequestDetailModel)

		assert.False(t, m.loading)
		assert.Nil(t, m.err)
		assert.NotNil(t, m.request)
		assert.Equal(t, "req-123", m.request.ID)
	})

	t.Run("handles request detail data error", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)

		msg := RequestDetailDataMsg{Err: errors.New("request not found")}
		newModel, _ := model.Update(msg)
		m := newModel.(*RequestDetailModel)

		assert.False(t, m.loading)
		assert.NotNil(t, m.err)
	})

	t.Run("handles approval result success", func(t *testing.T) {
		model, svc := newTestRequestDetailModel(t)
		svc.GetFunc = func(ctx context.Context, requestID string) (*evm.RequestStatus, error) {
			return &evm.RequestStatus{ID: requestID, Status: "completed"}, nil
		}

		model.request = &evm.RequestStatus{ID: "req-123", Status: "pending"}

		msg := ApprovalResultMsg{Success: true, Message: "Request approved", Err: nil}
		newModel, cmd := model.Update(msg)
		m := newModel.(*RequestDetailModel)

		assert.False(t, m.loading)
		assert.Contains(t, m.actionResult, "Request approved")
		assert.NotNil(t, cmd) // Reload command
	})

	t.Run("handles approval result error", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)

		msg := ApprovalResultMsg{Success: false, Err: errors.New("permission denied")}
		newModel, _ := model.Update(msg)
		m := newModel.(*RequestDetailModel)

		assert.Contains(t, m.actionResult, "Error")
	})

	t.Run("handles preview rule message", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)

		rule := &evm.Rule{
			ID:   "rule-preview",
			Name: "Auto-generated Rule",
			Type: "evm_address_list",
			Mode: "whitelist",
		}

		msg := PreviewRuleMsg{Rule: rule, Err: nil}
		newModel, _ := model.Update(msg)
		m := newModel.(*RequestDetailModel)

		assert.NotNil(t, m.previewRule)
		assert.Equal(t, "Auto-generated Rule", m.previewRule.Name)
		assert.Equal(t, "", m.previewError)
	})

	t.Run("handles preview rule error", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)

		msg := PreviewRuleMsg{Rule: nil, Err: errors.New("cannot generate rule")}
		newModel, _ := model.Update(msg)
		m := newModel.(*RequestDetailModel)

		assert.Nil(t, m.previewRule)
		assert.Contains(t, m.previewError, "cannot generate rule")
	})

	t.Run("handles approve key for pending request", func(t *testing.T) {
		model, svc := newTestRequestDetailModel(t)
		svc.PreviewRuleFunc = func(ctx context.Context, requestID string, req *evm.PreviewRuleRequest) (*evm.PreviewRuleResponse, error) {
			return &evm.PreviewRuleResponse{}, nil
		}

		model.request = &evm.RequestStatus{ID: "req-123", Status: "pending"}

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
		m := newModel.(*RequestDetailModel)

		assert.True(t, m.showApprove)
		assert.NotNil(t, cmd)
	})

	t.Run("handles reject key for pending request", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.request = &evm.RequestStatus{ID: "req-123", Status: "authorizing"}

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
		m := newModel.(*RequestDetailModel)

		assert.True(t, m.showReject)
	})

	t.Run("handles back navigation", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m := newModel.(*RequestDetailModel)

		assert.True(t, m.goBack)
	})

	t.Run("handles approve dialog - confirm", func(t *testing.T) {
		model, svc := newTestRequestDetailModel(t)
		svc.ApproveFunc = func(ctx context.Context, requestID string, req *evm.ApproveRequest) (*evm.ApproveResponse, error) {
			return &evm.ApproveResponse{Status: "completed"}, nil
		}

		model.showApprove = true
		model.request = &evm.RequestStatus{ID: "req-123"}

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
		m := newModel.(*RequestDetailModel)

		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})

	t.Run("handles approve dialog - cancel", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.showApprove = true

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
		m := newModel.(*RequestDetailModel)

		assert.False(t, m.showApprove)
	})

	t.Run("handles reject dialog - confirm", func(t *testing.T) {
		model, svc := newTestRequestDetailModel(t)
		svc.ApproveFunc = func(ctx context.Context, requestID string, req *evm.ApproveRequest) (*evm.ApproveResponse, error) {
			return &evm.ApproveResponse{Status: "rejected"}, nil
		}

		model.showReject = true
		model.request = &evm.RequestStatus{ID: "req-123"}

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
		m := newModel.(*RequestDetailModel)

		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})

	t.Run("handles generate rule toggle", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.showApprove = true
		model.generateRule = false

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("g")})
		m := newModel.(*RequestDetailModel)

		assert.True(t, m.generateRule)

		// Toggle off
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("g")})
		m = newModel.(*RequestDetailModel)

		assert.False(t, m.generateRule)
	})
}

func TestRequestDetailModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.loading = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders request details", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.loading = false
		model.request = &evm.RequestStatus{
			ID:            "req-123",
			Status:        "pending",
			ChainType:     "evm",
			SignerAddress: "0x1234567890",
			SignType:      "personal",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		model.SetSize(100, 30)

		view := model.View()
		assert.Contains(t, view, "Request Details")
		assert.Contains(t, view, "req-123")
		assert.Contains(t, view, "pending")
	})

	t.Run("renders approve dialog", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.loading = false
		model.showApprove = true
		model.width = 100
		model.height = 30
		model.request = &evm.RequestStatus{
			ID:            "req-123",
			SignerAddress: "0x1234",
			SignType:      "personal",
		}

		view := model.View()
		assert.Contains(t, view, "Approve Request")
	})

	t.Run("renders reject dialog", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.loading = false
		model.showReject = true
		model.width = 100
		model.height = 30
		model.request = &evm.RequestStatus{
			ID:            "req-123",
			SignerAddress: "0x1234",
			SignType:      "personal",
		}

		view := model.View()
		assert.Contains(t, view, "Reject Request")
	})

	t.Run("renders action buttons for pending status", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)
		model.loading = false
		model.request = &evm.RequestStatus{
			ID:        "req-123",
			Status:    "pending",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		model.SetSize(100, 30)

		view := model.View()
		assert.Contains(t, view, "Approve")
		assert.Contains(t, view, "Reject")
	})
}

func TestRequestDetailModel_LoadRequest(t *testing.T) {
	t.Run("sets loading state and resets fields", func(t *testing.T) {
		model, svc := newTestRequestDetailModel(t)
		svc.GetFunc = func(ctx context.Context, requestID string) (*evm.RequestStatus, error) {
			return &evm.RequestStatus{ID: requestID}, nil
		}

		model.showApprove = true
		model.actionResult = "some result"

		cmd := model.LoadRequest("req-123")
		assert.True(t, model.loading)
		assert.False(t, model.showApprove)
		assert.Equal(t, "", model.actionResult)
		assert.NotNil(t, cmd)
	})
}

func TestRequestDetailModel_ShouldGoBack(t *testing.T) {
	t.Run("returns goBack flag", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)

		assert.False(t, model.ShouldGoBack())

		model.goBack = true
		assert.True(t, model.ShouldGoBack())
	})
}

func TestRequestDetailModel_ResetGoBack(t *testing.T) {
	t.Run("resets goBack flag", func(t *testing.T) {
		model, _ := newTestRequestDetailModel(t)

		model.goBack = true
		model.ResetGoBack()
		assert.False(t, model.goBack)
	})
}
