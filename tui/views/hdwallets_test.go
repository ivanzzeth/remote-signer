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

func newTestHDWalletsModel(t *testing.T) (*HDWalletsModel, *mock.HDWalletService) {
	t.Helper()
	svc := mock.NewHDWalletService()
	model, err := newHDWalletsModelFromService(svc, context.Background())
	require.NoError(t, err)
	return model, svc
}

func TestNewHDWalletsModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewHDWalletsModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when service is nil", func(t *testing.T) {
		_, err := newHDWalletsModelFromService(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		svc := mock.NewHDWalletService()
		_, err := newHDWalletsModelFromService(svc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		require.NotNil(t, model)
		assert.True(t, model.loading)
		assert.Equal(t, 256, model.entropyBits)
	})
}

func TestHDWalletsModel_Init(t *testing.T) {
	t.Run("returns batch command", func(t *testing.T) {
		model, svc := newTestHDWalletsModel(t)
		svc.ListFunc = func(ctx context.Context) (*evm.ListHDWalletsResponse, error) {
			return &evm.ListHDWalletsResponse{Wallets: []evm.HDWalletResponse{}}, nil
		}

		cmd := model.Init()
		assert.NotNil(t, cmd)
	})
}

func TestHDWalletsModel_DataLoaded(t *testing.T) {
	t.Run("populates wallet list", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)

		wallets := []evm.HDWalletResponse{
			{PrimaryAddress: "0xabc123", BasePath: "m/44'/60'/0'/0", DerivedCount: 5},
			{PrimaryAddress: "0xdef456", BasePath: "m/44'/60'/0'/0", DerivedCount: 1},
		}

		msg := HDWalletsDataMsg{Wallets: wallets}
		newModel, _ := model.Update(msg)
		m := newModel.(*HDWalletsModel)

		assert.False(t, m.loading)
		assert.Nil(t, m.err)
		assert.Len(t, m.wallets, 2)
	})

	t.Run("handles data error", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)

		msg := HDWalletsDataMsg{Err: errors.New("connection failed")}
		newModel, _ := model.Update(msg)
		m := newModel.(*HDWalletsModel)

		assert.False(t, m.loading)
		assert.NotNil(t, m.err)
		assert.Contains(t, m.err.Error(), "connection failed")
	})
}

func TestHDWalletsModel_Navigation(t *testing.T) {
	t.Run("navigates up and down", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.wallets = []evm.HDWalletResponse{
			{PrimaryAddress: "0x1111"},
			{PrimaryAddress: "0x2222"},
			{PrimaryAddress: "0x3333"},
		}

		// Down
		model.selectedIdx = 0
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m := newModel.(*HDWalletsModel)
		assert.Equal(t, 1, m.selectedIdx)

		// Up
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*HDWalletsModel)
		assert.Equal(t, 0, m.selectedIdx)

		// Boundary - stay at 0
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*HDWalletsModel)
		assert.Equal(t, 0, m.selectedIdx)

		// Boundary - stay at last
		m.selectedIdx = 2
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = newModel.(*HDWalletsModel)
		assert.Equal(t, 2, m.selectedIdx)
	})

	t.Run("enter opens detail", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.wallets = []evm.HDWalletResponse{
			{PrimaryAddress: "0xabc123"},
		}
		model.selectedIdx = 0

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.True(t, m.ShouldOpenDetail())
		assert.Equal(t, "0xabc123", m.GetSelectedPrimaryAddr())

		m.ResetOpenDetail()
		assert.False(t, m.ShouldOpenDetail())
	})

	t.Run("enter does nothing with empty list", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.wallets = []evm.HDWalletResponse{}

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.False(t, m.ShouldOpenDetail())
	})
}

func TestHDWalletsModel_CreateFlow(t *testing.T) {
	t.Run("press c enters create mode", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})
		m := newModel.(*HDWalletsModel)
		assert.True(t, m.showCreate)
		assert.Equal(t, "create", m.createMode)
		assert.Equal(t, 0, m.createStep)
	})

	t.Run("select 256-bit entropy", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 0
		model.entropyIdx = 1 // 256-bit (default)

		// Press Enter to confirm 256-bit
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.Equal(t, 256, m.entropyBits)
		assert.Equal(t, 1, m.createStep) // Moved to password step
	})

	t.Run("select 128-bit entropy", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 0
		model.entropyIdx = 1 // start at 256

		// Navigate up to 128-bit and press Enter
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m := newModel.(*HDWalletsModel)
		assert.Equal(t, 0, m.entropyIdx)

		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = newModel.(*HDWalletsModel)
		assert.Equal(t, 128, m.entropyBits)
		assert.Equal(t, 1, m.createStep)
	})

	t.Run("password step advances to confirm when strong", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 1
		model.passwordInput.SetValue("Abcdef1!ghijklmn") // meets strength rules

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.Equal(t, 2, m.createStep) // Moved to confirm
	})

	t.Run("password step rejects weak password", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 1
		model.passwordInput.SetValue("short")

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.Equal(t, 1, m.createStep)
		assert.Contains(t, m.actionResult, "at least 16")
	})

	t.Run("empty password does not advance", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 1
		model.passwordInput.SetValue("")

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.Equal(t, 1, m.createStep) // Stays
	})

	t.Run("password mismatch shows error", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 2
		model.passwordInput.SetValue("Abcdef1!ghijklmn")
		model.confirmInput.SetValue("Abcdef1!ghijklmX")

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.Contains(t, m.actionResult, "Passwords do not match")
	})

	t.Run("password match triggers create", func(t *testing.T) {
		model, svc := newTestHDWalletsModel(t)
		svc.CreateFunc = func(ctx context.Context, req *evm.CreateHDWalletRequest) (*evm.HDWalletResponse, error) {
			return &evm.HDWalletResponse{PrimaryAddress: "0xnewwallet"}, nil
		}

		model.showCreate = true
		model.createMode = "create"
		model.createStep = 2
		model.entropyBits = 256
		model.passwordInput.SetValue("Abcdef1!ghijklmn")
		model.confirmInput.SetValue("Abcdef1!ghijklmn")

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})

	t.Run("create success resets form and refreshes", func(t *testing.T) {
		model, svc := newTestHDWalletsModel(t)
		svc.ListFunc = func(ctx context.Context) (*evm.ListHDWalletsResponse, error) {
			return &evm.ListHDWalletsResponse{Wallets: []evm.HDWalletResponse{}}, nil
		}
		model.showCreate = true
		model.createMode = "create"

		msg := HDWalletCreateMsg{
			Success: true,
			Message: "HD wallet created: 0xnewwallet",
			Wallet:  &evm.HDWalletResponse{PrimaryAddress: "0xnewwallet"},
		}

		newModel, cmd := model.Update(msg)
		m := newModel.(*HDWalletsModel)
		assert.False(t, m.showCreate)
		assert.Contains(t, m.actionResult, "HD wallet created")
		assert.NotNil(t, cmd)
	})

	t.Run("create error shows message", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true

		msg := HDWalletCreateMsg{
			Success: false,
			Err:     errors.New("permission denied"),
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*HDWalletsModel)
		assert.Contains(t, m.actionResult, "Error")
		assert.Contains(t, m.actionResult, "permission denied")
	})

	t.Run("esc cancels create", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 0

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m := newModel.(*HDWalletsModel)
		assert.False(t, m.showCreate)
	})

	t.Run("tab toggles password visibility", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 1

		assert.False(t, model.showPassword)

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
		m := newModel.(*HDWalletsModel)
		assert.True(t, m.showPassword)

		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = newModel.(*HDWalletsModel)
		assert.False(t, m.showPassword)
	})
}

func TestHDWalletsModel_ImportFlow(t *testing.T) {
	t.Run("press i enters import mode", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("i")})
		m := newModel.(*HDWalletsModel)
		assert.True(t, m.showCreate)
		assert.Equal(t, "import", m.createMode)
		assert.Equal(t, 0, m.createStep)
	})

	t.Run("mnemonic step advances to password", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true
		model.createMode = "import"
		model.createStep = 0
		model.mnemonicInput.SetValue("abandon abandon abandon about")

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.Equal(t, 1, m.createStep)
	})

	t.Run("empty mnemonic does not advance", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.showCreate = true
		model.createMode = "import"
		model.createStep = 0
		model.mnemonicInput.SetValue("")

		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.Equal(t, 0, m.createStep) // Stays
	})

	t.Run("import password match triggers import", func(t *testing.T) {
		model, svc := newTestHDWalletsModel(t)
		svc.ImportFunc = func(ctx context.Context, req *evm.CreateHDWalletRequest) (*evm.HDWalletResponse, error) {
			return &evm.HDWalletResponse{PrimaryAddress: "0ximported"}, nil
		}

		model.showCreate = true
		model.createMode = "import"
		model.createStep = 2
		model.mnemonicInput.SetValue("abandon abandon abandon about")
		model.passwordInput.SetValue("Abcdef1!ghijklmn")
		model.confirmInput.SetValue("Abcdef1!ghijklmn")

		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*HDWalletsModel)
		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})
}

func TestHDWalletsModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders wallet list", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.wallets = []evm.HDWalletResponse{
			{PrimaryAddress: "0xabc123456789", BasePath: "m/44'/60'/0'/0", DerivedCount: 5},
		}

		view := model.View()
		assert.Contains(t, view, "HD Wallets")
		assert.Contains(t, view, "0xabc123456789")
	})

	t.Run("renders empty wallet list", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.wallets = []evm.HDWalletResponse{}

		view := model.View()
		assert.Contains(t, view, "No HD wallets found")
	})

	t.Run("renders create form", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.showCreate = true
		model.createMode = "create"
		model.createStep = 0
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Create New HD Wallet")
		assert.Contains(t, view, "128-bit")
		assert.Contains(t, view, "256-bit")
	})

	t.Run("renders import form", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.loading = false
		model.showCreate = true
		model.createMode = "import"
		model.createStep = 0
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Import HD Wallet")
		assert.Contains(t, view, "Mnemonic")
	})
}

func TestHDWalletsModel_LoadData(t *testing.T) {
	t.Run("calls List and returns data", func(t *testing.T) {
		model, svc := newTestHDWalletsModel(t)
		svc.ListFunc = func(ctx context.Context) (*evm.ListHDWalletsResponse, error) {
			return &evm.ListHDWalletsResponse{
				Wallets: []evm.HDWalletResponse{
					{PrimaryAddress: "0xabc123"},
				},
			}, nil
		}

		cmd := model.loadData()
		msg := cmd()

		dataMsg, ok := msg.(HDWalletsDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
		assert.Len(t, dataMsg.Wallets, 1)
	})

	t.Run("returns error on failure", func(t *testing.T) {
		model, svc := newTestHDWalletsModel(t)
		svc.ListFunc = func(ctx context.Context) (*evm.ListHDWalletsResponse, error) {
			return nil, errors.New("network error")
		}

		cmd := model.loadData()
		msg := cmd()

		dataMsg, ok := msg.(HDWalletsDataMsg)
		require.True(t, ok)
		assert.NotNil(t, dataMsg.Err)
	})
}

func TestHDWalletsModel_Refresh(t *testing.T) {
	t.Run("sets loading and returns commands", func(t *testing.T) {
		model, svc := newTestHDWalletsModel(t)
		svc.ListFunc = func(ctx context.Context) (*evm.ListHDWalletsResponse, error) {
			return &evm.ListHDWalletsResponse{}, nil
		}

		model.loading = false
		cmd := model.Refresh()
		assert.True(t, model.loading)
		assert.NotNil(t, cmd)
	})
}

func TestHDWalletsModel_SetSize(t *testing.T) {
	t.Run("sets width and height", func(t *testing.T) {
		model, _ := newTestHDWalletsModel(t)
		model.SetSize(100, 50)
		assert.Equal(t, 100, model.width)
		assert.Equal(t, 50, model.height)
	})
}
