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

func newTestHDWalletDetailModel(t *testing.T) (*HDWalletDetailModel, *mock.HDWalletService) {
	t.Helper()
	svc := mock.NewHDWalletService()
	model, err := newHDWalletDetailModelFromService(svc, nil, context.Background())
	require.NoError(t, err)
	return model, svc
}

func TestNewHDWalletDetailModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewHDWalletDetailModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when HD wallet service is nil", func(t *testing.T) {
		_, err := newHDWalletDetailModelFromService(nil, nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HD wallet service is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		svc := mock.NewHDWalletService()
		_, err := newHDWalletDetailModelFromService(svc, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		require.NotNil(t, model)
	})
}

func TestHDWalletDetailModel_LoadWallet(t *testing.T) {
	t.Run("loads derived addresses", func(t *testing.T) {
		model, svc := newTestHDWalletDetailModel(t)
		svc.ListDerivedFunc = func(ctx context.Context, primaryAddr string) (*evm.ListDerivedAddressesResponse, error) {
			return &evm.ListDerivedAddressesResponse{
				Derived: []evm.SignerInfo{
					{Address: "0xaddr0", Type: "hd_wallet", Enabled: true},
					{Address: "0xaddr1", Type: "hd_wallet", Enabled: true},
				},
			}, nil
		}

		_ = model.LoadWallet(evm.HDWalletResponse{PrimaryAddress: "0xprimary"})
		assert.True(t, model.loading)
		assert.Equal(t, "0xprimary", model.primaryAddr)

		// Directly call loadWalletData to test the actual data fetching
		cmd := model.loadWalletData()
		msg := cmd()
		dataMsg, ok := msg.(HDWalletDetailDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
		assert.Len(t, dataMsg.Derived, 2)
	})

	t.Run("handles load error", func(t *testing.T) {
		model, svc := newTestHDWalletDetailModel(t)
		svc.ListDerivedFunc = func(ctx context.Context, primaryAddr string) (*evm.ListDerivedAddressesResponse, error) {
			return nil, errors.New("not found")
		}

		_ = model.LoadWallet(evm.HDWalletResponse{PrimaryAddress: "0xbadaddr"})
		cmd := model.loadWalletData()
		msg := cmd()
		dataMsg, ok := msg.(HDWalletDetailDataMsg)
		require.True(t, ok)
		assert.NotNil(t, dataMsg.Err)
	})

	t.Run("data message populates model", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.loading = true

		msg := HDWalletDetailDataMsg{
			Wallet: &evm.HDWalletResponse{
				PrimaryAddress: "0xprimary",
				DerivedCount:   2,
			},
			Derived: []evm.SignerInfo{
				{Address: "0xaddr0", Type: "hd_wallet", Enabled: true},
				{Address: "0xaddr1", Type: "hd_wallet", Enabled: true},
			},
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*HDWalletDetailModel)
		assert.False(t, m.loading)
		assert.NotNil(t, m.wallet)
		assert.Len(t, m.derived, 2)
	})

	t.Run("error message sets error", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.loading = true

		msg := HDWalletDetailDataMsg{Err: errors.New("failed")}
		newModel, _ := model.Update(msg)
		m := newModel.(*HDWalletDetailModel)
		assert.False(t, m.loading)
		assert.NotNil(t, m.err)
	})
}

func TestHDWalletDetailModel_DeriveSingle(t *testing.T) {
	t.Run("derive single address", func(t *testing.T) {
		model, svc := newTestHDWalletDetailModel(t)
		svc.DeriveAddressFunc = func(ctx context.Context, primaryAddr string, req *evm.DeriveAddressRequest) (*evm.DeriveAddressResponse, error) {
			assert.NotNil(t, req.Index)
			assert.Equal(t, uint32(5), *req.Index)
			return &evm.DeriveAddressResponse{
				Derived: []evm.SignerInfo{{Address: "0xnewaddr", Type: "hd_wallet", Enabled: true}},
			}, nil
		}
		svc.ListDerivedFunc = func(ctx context.Context, primaryAddr string) (*evm.ListDerivedAddressesResponse, error) {
			return &evm.ListDerivedAddressesResponse{}, nil
		}

		model.primaryAddr = "0xprimary"
		model.showDerive = true
		model.deriveMode = "single"
		model.indexInput.SetValue("5")

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletDetailModel)
		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})

	t.Run("invalid index shows error", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.showDerive = true
		model.deriveMode = "single"
		model.indexInput.SetValue("abc")

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletDetailModel)
		assert.Contains(t, m.actionResult, "Invalid index")
	})

	t.Run("derive success reloads wallet", func(t *testing.T) {
		model, svc := newTestHDWalletDetailModel(t)
		svc.ListDerivedFunc = func(ctx context.Context, primaryAddr string) (*evm.ListDerivedAddressesResponse, error) {
			return &evm.ListDerivedAddressesResponse{}, nil
		}
		model.primaryAddr = "0xprimary"
		model.seedWallet = evm.HDWalletResponse{PrimaryAddress: "0xprimary"}
		model.showDerive = true

		msg := HDWalletDeriveMsg{
			Success: true,
			Message: "Derived 1 address(es)",
			Derived: []evm.SignerInfo{{Address: "0xnew"}},
		}

		newModel, cmd := model.Update(msg)
		m := newModel.(*HDWalletDetailModel)
		assert.False(t, m.showDerive)
		// LoadWallet resets actionResult, so just check the derive form is cleared
		// and a reload command is returned
		assert.True(t, m.loading) // LoadWallet sets loading
		assert.NotNil(t, cmd)    // LoadWallet command
	})

	t.Run("derive error shows message", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.showDerive = true

		msg := HDWalletDeriveMsg{
			Success: false,
			Err:     errors.New("forbidden"),
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*HDWalletDetailModel)
		assert.Contains(t, m.actionResult, "Error")
	})
}

func TestHDWalletDetailModel_DeriveBatch(t *testing.T) {
	t.Run("batch derive addresses", func(t *testing.T) {
		model, svc := newTestHDWalletDetailModel(t)
		svc.DeriveAddressFunc = func(ctx context.Context, primaryAddr string, req *evm.DeriveAddressRequest) (*evm.DeriveAddressResponse, error) {
			assert.NotNil(t, req.Start)
			assert.NotNil(t, req.Count)
			assert.Equal(t, uint32(5), *req.Start)
			assert.Equal(t, uint32(10), *req.Count)
			return &evm.DeriveAddressResponse{
				Derived: make([]evm.SignerInfo, 10),
			}, nil
		}

		model.primaryAddr = "0xprimary"
		model.showDerive = true
		model.deriveMode = "batch"
		model.activeField = "start"
		model.startInput.SetValue("5")
		model.countInput.SetValue("10")

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletDetailModel)
		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})

	t.Run("invalid count shows error", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.showDerive = true
		model.deriveMode = "batch"
		model.startInput.SetValue("0")
		model.countInput.SetValue("101") // Over 100

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletDetailModel)
		assert.Contains(t, m.actionResult, "Invalid count")
	})

	t.Run("zero count shows error", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.showDerive = true
		model.deriveMode = "batch"
		model.startInput.SetValue("0")
		model.countInput.SetValue("0")

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletDetailModel)
		assert.Contains(t, m.actionResult, "Invalid count")
	})

	t.Run("tab switches between fields", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.showDerive = true
		model.deriveMode = "batch"
		model.activeField = "start"

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
		m := newModel.(*HDWalletDetailModel)
		assert.Equal(t, "count", m.activeField)

		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = newModel.(*HDWalletDetailModel)
		assert.Equal(t, "start", m.activeField)
	})
}

func TestHDWalletDetailModel_GoBack(t *testing.T) {
	t.Run("esc sets go back", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m := newModel.(*HDWalletDetailModel)
		assert.True(t, m.ShouldGoBack())

		m.ResetGoBack()
		assert.False(t, m.ShouldGoBack())
	})

	t.Run("esc in derive form cancels derive", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.showDerive = true
		model.deriveMode = "single"

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m := newModel.(*HDWalletDetailModel)
		assert.False(t, m.showDerive)
		assert.False(t, m.ShouldGoBack()) // Should cancel derive, not go back
	})
}

func TestHDWalletDetailModel_View(t *testing.T) {
	t.Run("renders loading", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.loading = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders detail with derived addresses", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.primaryAddr = "0xprimary123"
		model.wallet = &evm.HDWalletResponse{
			PrimaryAddress: "0xprimary123",
			DerivedCount:   2,
		}
		model.derived = []evm.SignerInfo{
			{Address: "0xaddr0", Type: "hd_wallet", Enabled: true},
			{Address: "0xaddr1", Type: "hd_wallet", Enabled: false},
		}

		view := model.View()
		assert.Contains(t, view, "HD Wallet Detail")
		assert.Contains(t, view, "0xprimary123")
		assert.Contains(t, view, "0xaddr0")
		assert.Contains(t, view, "0xaddr1")
	})

	t.Run("renders empty derived list", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.primaryAddr = "0xprimary"
		model.wallet = &evm.HDWalletResponse{PrimaryAddress: "0xprimary"}
		model.derived = []evm.SignerInfo{}

		view := model.View()
		assert.Contains(t, view, "No derived addresses")
	})

	t.Run("renders derive single form", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.loading = false
		model.showDerive = true
		model.deriveMode = "single"
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Derive Address")
		assert.Contains(t, view, "derivation index")
	})

	t.Run("renders batch derive form", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.loading = false
		model.showDerive = true
		model.deriveMode = "batch"
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Batch Derive")
		assert.Contains(t, view, "Start index")
		assert.Contains(t, view, "Count")
	})
}

func TestHDWalletDetailModel_Navigation(t *testing.T) {
	t.Run("d opens single derive form", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
		m := newModel.(*HDWalletDetailModel)
		assert.True(t, m.showDerive)
		assert.Equal(t, "single", m.deriveMode)
	})

	t.Run("b opens batch derive form", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("b")})
		m := newModel.(*HDWalletDetailModel)
		assert.True(t, m.showDerive)
		assert.Equal(t, "batch", m.deriveMode)
	})

	t.Run("up/down navigates derived list", func(t *testing.T) {
		model, _ := newTestHDWalletDetailModel(t)
		model.derived = []evm.SignerInfo{
			{Address: "0x1"},
			{Address: "0x2"},
			{Address: "0x3"},
		}

		model.selectedIdx = 0
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m := newModel.(*HDWalletDetailModel)
		assert.Equal(t, 1, m.selectedIdx)

		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*HDWalletDetailModel)
		assert.Equal(t, 0, m.selectedIdx)
	})
}

