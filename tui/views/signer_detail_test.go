package views

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func newTestSignerDetailModel(t *testing.T) *SignerDetailModel {
	t.Helper()
	model, err := NewSignerDetailModel(context.Background())
	require.NoError(t, err)
	model.SetSize(120, 40)
	return model
}

func TestNewSignerDetailModel(t *testing.T) {
	t.Run("returns error when context is nil", func(t *testing.T) {
		_, err := NewSignerDetailModel(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, err := NewSignerDetailModel(context.Background())
		require.NoError(t, err)
		require.NotNil(t, model)
		assert.Nil(t, model.signer)
		assert.False(t, model.goBack)
	})
}

func TestSignerDetailModel_LoadSigner(t *testing.T) {
	t.Run("sets signer data correctly", func(t *testing.T) {
		model := newTestSignerDetailModel(t)

		signer := evm.Signer{
			Address: "0x1111111111111111111111111111111111111111",
			Type:    "private_key",
			Enabled: true,
			AllowedKeys: []evm.AllowedKeyInfo{
				{ID: "admin-key", Name: "Admin Key", AccessType: "unrestricted"},
			},
		}

		model.LoadSigner(signer)
		require.NotNil(t, model.signer)
		assert.Equal(t, "0x1111111111111111111111111111111111111111", model.signer.Address)
		assert.Equal(t, "private_key", model.signer.Type)
		assert.True(t, model.signer.Enabled)
		assert.Len(t, model.signer.AllowedKeys, 1)
		assert.False(t, model.goBack)
	})

	t.Run("resets goBack flag on load", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		model.goBack = true

		model.LoadSigner(evm.Signer{Address: "0x1234"})
		assert.False(t, model.goBack)
	})
}

func TestSignerDetailModel_View_BasicInfo(t *testing.T) {
	t.Run("renders address, type, status for enabled signer", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		model.LoadSigner(evm.Signer{
			Address: "0x1111111111111111111111111111111111111111",
			Type:    "private_key",
			Enabled: true,
		})

		view := model.View()
		assert.Contains(t, view, "Signer Detail")
		assert.Contains(t, view, "0x1111111111111111111111111111111111111111")
		assert.Contains(t, view, "private_key")
		assert.Contains(t, view, "Enabled")
	})

	t.Run("renders disabled status", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		model.LoadSigner(evm.Signer{
			Address: "0x1234",
			Type:    "keystore",
			Enabled: false,
		})

		view := model.View()
		assert.Contains(t, view, "Disabled")
	})

	t.Run("returns placeholder when no signer loaded", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		view := model.View()
		assert.Equal(t, "No signer loaded", view)
	})
}

func TestSignerDetailModel_View_AccessControl(t *testing.T) {
	t.Run("renders access table when AllowedKeys present", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		model.LoadSigner(evm.Signer{
			Address: "0x1111111111111111111111111111111111111111",
			Type:    "private_key",
			Enabled: true,
			AllowedKeys: []evm.AllowedKeyInfo{
				{ID: "admin-key", Name: "Admin Key", AccessType: "unrestricted"},
				{ID: "readonly-key", Name: "Read Only Key", AccessType: "unrestricted"},
				{ID: "dev-key", Name: "Dev Key", AccessType: "explicit"},
			},
		})

		view := model.View()
		assert.Contains(t, view, "Access Control")
		assert.Contains(t, view, "3 API key(s) have access")
		assert.Contains(t, view, "Admin Key")
		assert.Contains(t, view, "Read Only Key")
		assert.Contains(t, view, "Dev Key")
		assert.Contains(t, view, "all signers")
		assert.Contains(t, view, "explicit")
	})
}

func TestSignerDetailModel_View_NoAccessControl(t *testing.T) {
	t.Run("no access section for non-admin view", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		model.LoadSigner(evm.Signer{
			Address: "0x2222222222222222222222222222222222222222",
			Type:    "keystore",
			Enabled: true,
		})

		view := model.View()
		assert.NotContains(t, view, "Access Control")
		assert.NotContains(t, view, "API key")
	})
}

func TestSignerDetailModel_BackNavigation(t *testing.T) {
	t.Run("Esc sets goBack", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		model.LoadSigner(evm.Signer{Address: "0x1234", Type: "keystore", Enabled: true})

		assert.False(t, model.ShouldGoBack())

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m := newModel.(*SignerDetailModel)
		assert.True(t, m.ShouldGoBack())
	})

	t.Run("Backspace sets goBack", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		model.LoadSigner(evm.Signer{Address: "0x1234", Type: "keystore", Enabled: true})

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyBackspace})
		m := newModel.(*SignerDetailModel)
		assert.True(t, m.ShouldGoBack())
	})

	t.Run("ResetGoBack clears flag", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		model.goBack = true

		model.ResetGoBack()
		assert.False(t, model.ShouldGoBack())
	})
}

func TestSignerDetailModel_IsCapturingInput(t *testing.T) {
	t.Run("always returns false", func(t *testing.T) {
		model := newTestSignerDetailModel(t)
		assert.False(t, model.IsCapturingInput())

		model.LoadSigner(evm.Signer{Address: "0x1234", Type: "keystore", Enabled: true})
		assert.False(t, model.IsCapturingInput())
	})
}
