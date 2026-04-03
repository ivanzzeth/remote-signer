package views

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/mock"
)

func TestFormatHDWalletRoleLine(t *testing.T) {
	ix0 := uint32(0)
	ix3 := uint32(3)
	assert.Equal(t, "", formatHDWalletRoleLine(evm.Signer{Type: "keystore"}))
	assert.Equal(t, "HD: primary", formatHDWalletRoleLine(evm.Signer{Type: "hd_wallet", HDDerivationIndex: &ix0}))
	assert.Equal(t, "HD: derived #3", formatHDWalletRoleLine(evm.Signer{Type: "hd_wallet", HDDerivationIndex: &ix3}))
	assert.Equal(t, "HD: ?", formatHDWalletRoleLine(evm.Signer{Type: "hd_wallet"}))
}

func newTestSignersModel(t *testing.T) (*SignersModel, *mock.SignerService) {
	t.Helper()
	svc := mock.NewSignerService()
	hdSvc := mock.NewHDWalletService()
	model, err := newSignersModelFromService(svc, hdSvc, context.Background())
	require.NoError(t, err)
	return model, svc
}

func newTestSignersModelWithHD(t *testing.T) (*SignersModel, *mock.SignerService, *mock.HDWalletService) {
	t.Helper()
	svc := mock.NewSignerService()
	hdSvc := mock.NewHDWalletService()
	model, err := newSignersModelFromService(svc, hdSvc, context.Background())
	require.NoError(t, err)
	return model, svc, hdSvc
}

func TestNewSignersModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewSignersModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		svc := mock.NewSignerService()
		hdSvc := mock.NewHDWalletService()
		_, err := newSignersModelFromService(svc, hdSvc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		require.NotNil(t, model)
		assert.True(t, model.loading)
		assert.Equal(t, 20, model.limit)
	})
}

func TestSignersModel_Update(t *testing.T) {
	t.Run("handles signers data message", func(t *testing.T) {
		model, _ := newTestSignersModel(t)

		signers := []evm.Signer{
			{Address: "0x1234567890123456789012345678901234567890", Type: "keystore", Enabled: true},
			{Address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", Type: "private_key", Enabled: true},
		}

		msg := SignersDataMsg{
			Signers: signers,
			Total:   2,
			HasMore: false,
			Err:     nil,
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*SignersModel)

		assert.False(t, m.loading)
		assert.Nil(t, m.err)
		assert.Len(t, m.signers, 2)
		assert.Equal(t, 2, m.total)
		assert.False(t, m.hasMore)
	})

	t.Run("handles signers data error", func(t *testing.T) {
		model, _ := newTestSignersModel(t)

		msg := SignersDataMsg{
			Err: errors.New("connection failed"),
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*SignersModel)

		assert.False(t, m.loading)
		assert.NotNil(t, m.err)
		assert.Contains(t, m.err.Error(), "connection failed")
	})

	t.Run("handles signer create success", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		svc.ListFunc = func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
			return &evm.ListSignersResponse{Signers: []evm.Signer{}, Total: 0}, nil
		}
		model.showCreate = true
		model.createStep = 2

		msg := SignerCreateMsg{
			Signer:  &evm.Signer{Address: "0x1234567890123456789012345678901234567890"},
			Success: true,
			Message: "Signer created: 0x1234567890123456789012345678901234567890",
			Err:     nil,
		}

		newModel, cmd := model.Update(msg)
		m := newModel.(*SignersModel)

		// On success, showCreate is reset and Refresh() is called (loading becomes true)
		assert.True(t, m.loading) // Refresh was called, so loading is now true
		assert.False(t, m.showCreate)
		assert.Equal(t, 0, m.createStep)
		assert.Contains(t, m.actionResult, "Signer created")
		assert.NotNil(t, cmd) // Refresh command is returned
	})

	t.Run("handles signer create error", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.showCreate = true

		msg := SignerCreateMsg{
			Success: false,
			Err:     errors.New("password too weak"),
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*SignersModel)

		assert.False(t, m.loading)
		assert.Contains(t, m.actionResult, "Error")
	})

	t.Run("handles navigation keys", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		model.signers = []evm.Signer{
			{Address: "0x1111"},
			{Address: "0x2222"},
			{Address: "0x3333"},
		}

		// Test down key
		model.selectedIdx = 0
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m := newModel.(*SignersModel)
		assert.Equal(t, 1, m.selectedIdx)

		// Test up key
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*SignersModel)
		assert.Equal(t, 0, m.selectedIdx)

		// Test down again
		m.selectedIdx = 1
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = newModel.(*SignersModel)
		assert.Equal(t, 2, m.selectedIdx)

		// Test boundary - already at last
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = newModel.(*SignersModel)
		assert.Equal(t, 2, m.selectedIdx) // Should stay at last

		// Test up at first
		m.selectedIdx = 0
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*SignersModel)
		assert.Equal(t, 0, m.selectedIdx) // Should stay at first
	})

	t.Run("handles filter mode", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false

		// Press 'f' to enter filter mode
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
		m := newModel.(*SignersModel)
		assert.True(t, m.showFilter)

		// Press 'esc' to exit filter mode
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m = newModel.(*SignersModel)
		assert.False(t, m.showFilter)
	})

	t.Run("handles create mode", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false

		// Press '+' to enter create mode
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("+")})
		m := newModel.(*SignersModel)
		assert.True(t, m.showCreate)
		assert.Equal(t, 0, m.createStep)

		// Press 'esc' to exit create mode
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
		m = newModel.(*SignersModel)
		assert.False(t, m.showCreate)
	})

	t.Run("handles create flow - select type", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		model.showCreate = true
		model.createStep = 0
		model.typeIdx = 0 // keystore

		// Press Enter to select keystore type
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*SignersModel)
		assert.Equal(t, 1, m.createStep)
		assert.Equal(t, "keystore", m.selectedType)
	})

	t.Run("handles clear filter", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		svc.ListFunc = func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
			return &evm.ListSignersResponse{Signers: []evm.Signer{}, Total: 0}, nil
		}

		model.loading = false
		model.typeFilter = "keystore"
		model.offset = 10

		// Press 'c' to clear filters
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})
		m := newModel.(*SignersModel)
		assert.Equal(t, "", m.typeFilter)
		assert.Equal(t, 0, m.offset)
	})
}

func TestSignersModel_View(t *testing.T) {
	t.Run("renders loading state", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders signers list", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.signers = []evm.Signer{
			{Address: "0x1234567890123456789012345678901234567890", Type: "keystore", Enabled: true},
		}
		model.total = 1

		view := model.View()
		assert.Contains(t, view, "Signers")
		assert.Contains(t, view, "0x1234567890123456789012345678901234567890")
		assert.Contains(t, view, "keystore")
	})

	t.Run("renders empty signers list", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.signers = []evm.Signer{}
		model.total = 0

		view := model.View()
		assert.Contains(t, view, "No signers found")
	})

	t.Run("renders filter input", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		model.showFilter = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Filter")
	})

	t.Run("renders create form", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		model.showCreate = true
		model.createStep = 0
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Create New Signer")
	})

	t.Run("renders pagination info", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		model.width = 150
		model.height = 30
		model.signers = []evm.Signer{
			{Address: "0x1111", Type: "keystore", Enabled: true},
			{Address: "0x2222", Type: "keystore", Enabled: true},
		}
		model.total = 5
		model.hasMore = true

		view := model.View()
		assert.Contains(t, view, "Showing")
		assert.Contains(t, view, "more available")
	})
}

func TestSignersModel_LoadData(t *testing.T) {
	t.Run("calls client ListSigners with correct filter", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		var capturedFilter *evm.ListSignersFilter
		svc.ListFunc = func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
			capturedFilter = filter
			return &evm.ListSignersResponse{
				Signers: []evm.Signer{},
				Total:   0,
			}, nil
		}

		model.typeFilter = "keystore"
		model.offset = 10
		model.limit = 20

		// Execute loadData
		cmd := model.loadData()
		msg := cmd()

		require.NotNil(t, capturedFilter)
		assert.Equal(t, "keystore", capturedFilter.Type)
		assert.Equal(t, 10, capturedFilter.Offset)
		assert.Equal(t, 20, capturedFilter.Limit)
		assert.True(t, capturedFilter.ExcludeHDDerived, "default should exclude HD derived via API")

		dataMsg, ok := msg.(SignersDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
	})

	t.Run("returns error on client failure", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		svc.ListFunc = func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
			return nil, errors.New("network error")
		}

		cmd := model.loadData()
		msg := cmd()

		dataMsg, ok := msg.(SignersDataMsg)
		require.True(t, ok)
		assert.NotNil(t, dataMsg.Err)
		assert.Contains(t, dataMsg.Err.Error(), "network error")
	})
}

func TestSignersModel_CreateSigner(t *testing.T) {
	t.Run("calls client CreateSigner with keystore params", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		var capturedReq *evm.CreateSignerRequest
		svc.CreateFunc = func(ctx context.Context, req *evm.CreateSignerRequest) (*evm.Signer, error) {
			capturedReq = req
			return &evm.Signer{
				Address: "0x1234567890123456789012345678901234567890",
				Type:    "keystore",
				Enabled: true,
			}, nil
		}

		cmd := model.createSigner("keystore", "testpassword123")
		msg := cmd()

		require.NotNil(t, capturedReq)
		assert.Equal(t, "keystore", capturedReq.Type)
		require.NotNil(t, capturedReq.Keystore)
		assert.Equal(t, "testpassword123", capturedReq.Keystore.Password)

		createMsg, ok := msg.(SignerCreateMsg)
		require.True(t, ok)
		assert.True(t, createMsg.Success)
		assert.NotNil(t, createMsg.Signer)
	})

	t.Run("returns error on client failure", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		svc.CreateFunc = func(ctx context.Context, req *evm.CreateSignerRequest) (*evm.Signer, error) {
			return nil, errors.New("permission denied")
		}

		cmd := model.createSigner("keystore", "password")
		msg := cmd()

		createMsg, ok := msg.(SignerCreateMsg)
		require.True(t, ok)
		assert.False(t, createMsg.Success)
		assert.NotNil(t, createMsg.Err)
		assert.Contains(t, createMsg.Err.Error(), "permission denied")
	})
}

func TestSignersModel_Refresh(t *testing.T) {
	t.Run("sets loading and returns commands", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		svc.ListFunc = func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
			return &evm.ListSignersResponse{Signers: []evm.Signer{}, Total: 0}, nil
		}

		model.loading = false

		cmd := model.Refresh()
		assert.True(t, model.loading)
		assert.NotNil(t, cmd)
	})
}

func TestSignersModel_SetSize(t *testing.T) {
	t.Run("sets width and height", func(t *testing.T) {
		model, _ := newTestSignersModel(t)

		model.SetSize(100, 50)
		assert.Equal(t, 100, model.width)
		assert.Equal(t, 50, model.height)
	})
}

func TestSignersModel_Init(t *testing.T) {
	t.Run("returns batch command", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		svc.ListFunc = func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
			time.Sleep(10 * time.Millisecond) // Simulate async operation
			return &evm.ListSignersResponse{Signers: []evm.Signer{}, Total: 0}, nil
		}

		cmd := model.Init()
		assert.NotNil(t, cmd)
	})
}

func TestSignersModel_CreateHDWalletDerive(t *testing.T) {
	t.Run("select HD wallet type loads wallet list", func(t *testing.T) {
		model, _, hdSvc := newTestSignersModelWithHD(t)
		hdSvc.ListFunc = func(ctx context.Context) (*evm.ListHDWalletsResponse, error) {
			return &evm.ListHDWalletsResponse{
				Wallets: []evm.HDWalletResponse{
					{PrimaryAddress: "0xabc123", BasePath: "m/44'/60'/0'/0", DerivedCount: 3},
				},
			}, nil
		}
		model.loading = false
		model.showCreate = true
		model.createStep = 0
		model.typeIdx = 0

		// Navigate down to HD wallet option and press Enter
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m := newModel.(*SignersModel)
		assert.Equal(t, 1, m.typeIdx)

		newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = newModel.(*SignersModel)
		assert.Equal(t, "hd_wallet", m.selectedType)
		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})

	t.Run("HD wallet list loaded shows picker", func(t *testing.T) {
		model, _, _ := newTestSignersModelWithHD(t)
		model.showCreate = true
		model.selectedType = "hd_wallet"
		model.createStep = 1

		msg := SignerHDWalletListMsg{
			Wallets: []evm.HDWalletResponse{
				{PrimaryAddress: "0xabc123", BasePath: "m/44'/60'/0'/0", DerivedCount: 3},
				{PrimaryAddress: "0xdef456", BasePath: "m/44'/60'/0'/0", DerivedCount: 1},
			},
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*SignersModel)
		assert.Equal(t, 2, m.createStep)
		assert.Len(t, m.hdWallets, 2)
		assert.Equal(t, 0, m.hdWalletIdx)
	})

	t.Run("HD wallet list empty shows error", func(t *testing.T) {
		model, _, _ := newTestSignersModelWithHD(t)
		model.showCreate = true
		model.selectedType = "hd_wallet"
		model.createStep = 1

		msg := SignerHDWalletListMsg{
			Wallets: []evm.HDWalletResponse{},
		}

		newModel, _ := model.Update(msg)
		m := newModel.(*SignersModel)
		assert.Equal(t, 0, m.createStep) // Goes back to type selection
		assert.Contains(t, m.actionResult, "No HD wallets found")
	})

	t.Run("HD wallet picker navigation and selection", func(t *testing.T) {
		model, _, _ := newTestSignersModelWithHD(t)
		model.showCreate = true
		model.selectedType = "hd_wallet"
		model.createStep = 2
		model.hdWallets = []evm.HDWalletResponse{
			{PrimaryAddress: "0xabc123", DerivedCount: 3},
			{PrimaryAddress: "0xdef456", DerivedCount: 1},
		}
		model.hdWalletIdx = 0

		// Navigate down
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m := newModel.(*SignersModel)
		assert.Equal(t, 1, m.hdWalletIdx)

		// Navigate up
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = newModel.(*SignersModel)
		assert.Equal(t, 0, m.hdWalletIdx)

		// Select wallet
		newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = newModel.(*SignersModel)
		assert.Equal(t, 3, m.createStep) // Moved to derive index step
	})

	t.Run("HD derive index submits and refreshes", func(t *testing.T) {
		model, svc, hdSvc := newTestSignersModelWithHD(t)
		svc.ListFunc = func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
			return &evm.ListSignersResponse{Signers: []evm.Signer{}, Total: 0}, nil
		}
		hdSvc.DeriveAddressFunc = func(ctx context.Context, primaryAddr string, req *evm.DeriveAddressRequest) (*evm.DeriveAddressResponse, error) {
			return &evm.DeriveAddressResponse{
				Derived: []evm.SignerInfo{{Address: "0xnewaddr", Type: "hd_wallet", Enabled: true}},
			}, nil
		}

		model.showCreate = true
		model.selectedType = "hd_wallet"
		model.createStep = 3
		model.hdWallets = []evm.HDWalletResponse{
			{PrimaryAddress: "0xabc123", DerivedCount: 3},
		}
		model.hdWalletIdx = 0
		model.indexInput.SetValue("5")

		// Press enter to derive
		newModel, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m := newModel.(*SignersModel)
		assert.True(t, m.loading)
		assert.NotNil(t, cmd)
	})

	t.Run("HD derive success resets create and refreshes", func(t *testing.T) {
		model, svc, _ := newTestSignersModelWithHD(t)
		svc.ListFunc = func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
			return &evm.ListSignersResponse{Signers: []evm.Signer{}, Total: 0}, nil
		}

		model.showCreate = true
		model.selectedType = "hd_wallet"
		model.createStep = 3

		msg := SignerHDDeriveMsg{
			Success: true,
			Message: "Derived signer: 0xnewaddr",
			Derived: []evm.SignerInfo{{Address: "0xnewaddr", Type: "hd_wallet", Enabled: true}},
		}

		newModel, cmd := model.Update(msg)
		m := newModel.(*SignersModel)
		assert.False(t, m.showCreate)
		assert.Contains(t, m.actionResult, "Derived signer")
		assert.NotNil(t, cmd) // Refresh command
	})

	t.Run("render create form shows HD wallet option", func(t *testing.T) {
		model, _, _ := newTestSignersModelWithHD(t)
		model.loading = false
		model.showCreate = true
		model.createStep = 0
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Keystore")
		assert.Contains(t, view, "Derive from HD Wallet")
	})
}


func TestValidatePassword(t *testing.T) {
	t.Run("rejects short password", func(t *testing.T) {
		errMsg, warnMsg := validatePassword("Abc1!xyz")
		assert.Contains(t, errMsg, "at least 16 characters")
		assert.Empty(t, warnMsg)
	})

	t.Run("rejects exactly 15 characters", func(t *testing.T) {
		errMsg, _ := validatePassword("Abcdef1!ghijklm") // 15 chars
		assert.Contains(t, errMsg, "at least 16 characters")
	})

	t.Run("rejects missing uppercase", func(t *testing.T) {
		errMsg, _ := validatePassword("abcdefgh1234!@#$")
		assert.Contains(t, errMsg, "uppercase letter")
	})

	t.Run("rejects missing lowercase", func(t *testing.T) {
		errMsg, _ := validatePassword("ABCDEFGH1234!@#$")
		assert.Contains(t, errMsg, "lowercase letter")
	})

	t.Run("rejects missing digit", func(t *testing.T) {
		errMsg, _ := validatePassword("AbcDefGhIjKl!@#$")
		assert.Contains(t, errMsg, "digit")
	})

	t.Run("rejects missing symbol", func(t *testing.T) {
		errMsg, _ := validatePassword("AbcDefGh12345678")
		assert.Contains(t, errMsg, "symbol")
	})

	t.Run("rejects multiple missing classes", func(t *testing.T) {
		errMsg, _ := validatePassword("abcdefghijklmnop") // no upper, digit, symbol
		assert.Contains(t, errMsg, "uppercase letter")
		assert.Contains(t, errMsg, "digit")
		assert.Contains(t, errMsg, "symbol")
	})

	t.Run("accepts 16-char valid password with warning", func(t *testing.T) {
		errMsg, warnMsg := validatePassword("Abcdef1!ghijklmn") // 16 chars
		assert.Empty(t, errMsg)
		assert.Contains(t, warnMsg, "24+")
	})

	t.Run("accepts 24-char valid password without warning", func(t *testing.T) {
		errMsg, warnMsg := validatePassword("Abcdef1!ghijklmnopqrstuv") // 24 chars
		assert.Empty(t, errMsg)
		assert.Empty(t, warnMsg)
	})

	t.Run("accepts long password without warning", func(t *testing.T) {
		errMsg, warnMsg := validatePassword("MyV3ry$ecureP@ssword!WithExtra1234")
		assert.Empty(t, errMsg)
		assert.Empty(t, warnMsg)
	})
}

func TestUnlockErrShouldCountFailedAttempt(t *testing.T) {
	assert.False(t, unlockErrShouldCountFailedAttempt(errors.New("network")))
	assert.False(t, unlockErrShouldCountFailedAttempt(&client.APIError{StatusCode: http.StatusForbidden}))
	assert.False(t, unlockErrShouldCountFailedAttempt(&client.APIError{StatusCode: http.StatusNotFound}))
	assert.False(t, unlockErrShouldCountFailedAttempt(&client.APIError{StatusCode: http.StatusConflict}))
	assert.True(t, unlockErrShouldCountFailedAttempt(&client.APIError{StatusCode: http.StatusInternalServerError}))
}

func TestSignersModel_UnlockRateLimiting(t *testing.T) {
	t.Run("blocks after max failed attempts", func(t *testing.T) {
		model, svc := newTestSignersModel(t)
		model.loading = false
		model.signers = []evm.Signer{
			{Address: "0x1111", Type: "keystore", Enabled: false, Locked: true},
		}
		model.selectedIdx = 0

		svc.UnlockFunc = func(ctx context.Context, address string, req *evm.UnlockSignerRequest) (*evm.Signer, error) {
			return nil, &client.APIError{StatusCode: http.StatusInternalServerError, Code: "unlock_failed", Message: "wrong password"}
		}

		addr := model.signers[0].Address

		// Simulate maxUnlockAttempts failures (API returns 500 for bad password today)
		for i := 0; i < maxUnlockAttempts; i++ {
			msg := SignerUnlockMsg{Address: addr, Success: false, Err: &client.APIError{StatusCode: http.StatusInternalServerError, Code: "unlock_failed", Message: "wrong password"}}
			model.Update(msg)
		}

		// Now try to open unlock form — should be blocked by cooldown
		model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("u")})
		assert.False(t, model.showUnlock)
		assert.Contains(t, model.actionResult, "Too many failed attempts")
	})

	t.Run("success clears rate limit state", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		addr := "0x1111"
		model.signers = []evm.Signer{
			{Address: addr, Type: "keystore", Enabled: false, Locked: true},
		}
		model.selectedIdx = 0

		// Add some failed attempts
		model.unlockAttempts[addr] = 3

		// Success message
		msg := SignerUnlockMsg{Address: addr, Success: true, Message: "Signer unlocked"}
		model.Update(msg)

		// Attempts should be cleared
		assert.Equal(t, 0, model.unlockAttempts[addr])
		_, hasCooldown := model.unlockCooldownUtil[addr]
		assert.False(t, hasCooldown)
	})

	t.Run("cooldown expires after duration", func(t *testing.T) {
		model, _ := newTestSignersModel(t)
		model.loading = false
		addr := "0x1111"
		model.signers = []evm.Signer{
			{Address: addr, Type: "keystore", Enabled: false, Locked: true},
		}
		model.selectedIdx = 0

		// Set cooldown in the past (already expired)
		model.unlockCooldownUtil[addr] = time.Now().Add(-1 * time.Second)

		// Should be able to open unlock form
		model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("u")})
		assert.True(t, model.showUnlock)
	})
}

