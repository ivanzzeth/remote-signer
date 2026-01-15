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

func TestNewSignersModel(t *testing.T) {
	t.Run("returns error when client is nil", func(t *testing.T) {
		_, err := NewSignersModel(nil, context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client is required")
	})

	t.Run("returns error when context is nil", func(t *testing.T) {
		mockClient := client.NewMockClient()
		_, err := NewSignersModel(mockClient, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context is required")
	})

	t.Run("creates model successfully", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		require.NotNil(t, model)
		assert.True(t, model.loading)
		assert.Equal(t, 20, model.limit)
	})
}

func TestSignersModel_Update(t *testing.T) {
	t.Run("handles signers data message", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)

		signers := []client.Signer{
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
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)

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
		mockClient := client.NewMockClient()
		mockClient.ListSignersFunc = func(ctx context.Context, filter *client.ListSignersFilter) (*client.ListSignersResponse, error) {
			return &client.ListSignersResponse{Signers: []client.Signer{}, Total: 0}, nil
		}
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.showCreate = true
		model.createStep = 2

		msg := SignerCreateMsg{
			Signer:  &client.Signer{Address: "0x1234567890123456789012345678901234567890"},
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
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
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
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.signers = []client.Signer{
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
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
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
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
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
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.showCreate = true
		model.createStep = 0

		// Press '1' to select keystore type
		newModel, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")})
		m := newModel.(*SignersModel)
		assert.Equal(t, 1, m.createStep)
		assert.Equal(t, "keystore", m.selectedType)
	})

	t.Run("handles clear filter", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.ListSignersFunc = func(ctx context.Context, filter *client.ListSignersFilter) (*client.ListSignersResponse, error) {
			return &client.ListSignersResponse{Signers: []client.Signer{}, Total: 0}, nil
		}

		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
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
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Loading")
	})

	t.Run("renders error state", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.err = errors.New("test error")
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Error")
	})

	t.Run("renders signers list", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.width = 150
		model.height = 30
		model.signers = []client.Signer{
			{Address: "0x1234567890123456789012345678901234567890", Type: "keystore", Enabled: true},
		}
		model.total = 1

		view := model.View()
		assert.Contains(t, view, "Signers")
		assert.Contains(t, view, "0x1234567890123456789012345678901234567890")
		assert.Contains(t, view, "keystore")
	})

	t.Run("renders empty signers list", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.width = 150
		model.height = 30
		model.signers = []client.Signer{}
		model.total = 0

		view := model.View()
		assert.Contains(t, view, "No signers found")
	})

	t.Run("renders filter input", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.showFilter = true
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Filter")
	})

	t.Run("renders create form", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.showCreate = true
		model.createStep = 0
		model.width = 100
		model.height = 30

		view := model.View()
		assert.Contains(t, view, "Create New Signer")
	})

	t.Run("renders pagination info", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false
		model.width = 150
		model.height = 30
		model.signers = []client.Signer{
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
		mockClient := client.NewMockClient()
		var capturedFilter *client.ListSignersFilter
		mockClient.ListSignersFunc = func(ctx context.Context, filter *client.ListSignersFilter) (*client.ListSignersResponse, error) {
			capturedFilter = filter
			return &client.ListSignersResponse{
				Signers: []client.Signer{},
				Total:   0,
			}, nil
		}

		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
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

		dataMsg, ok := msg.(SignersDataMsg)
		require.True(t, ok)
		assert.Nil(t, dataMsg.Err)
	})

	t.Run("returns error on client failure", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.ListSignersFunc = func(ctx context.Context, filter *client.ListSignersFilter) (*client.ListSignersResponse, error) {
			return nil, errors.New("network error")
		}

		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)

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
		mockClient := client.NewMockClient()
		var capturedReq *client.CreateSignerRequest
		mockClient.CreateSignerFunc = func(ctx context.Context, req *client.CreateSignerRequest) (*client.Signer, error) {
			capturedReq = req
			return &client.Signer{
				Address: "0x1234567890123456789012345678901234567890",
				Type:    "keystore",
				Enabled: true,
			}, nil
		}

		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)

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
		mockClient := client.NewMockClient()
		mockClient.CreateSignerFunc = func(ctx context.Context, req *client.CreateSignerRequest) (*client.Signer, error) {
			return nil, errors.New("permission denied")
		}

		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)

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
		mockClient := client.NewMockClient()
		mockClient.ListSignersFunc = func(ctx context.Context, filter *client.ListSignersFilter) (*client.ListSignersResponse, error) {
			return &client.ListSignersResponse{Signers: []client.Signer{}, Total: 0}, nil
		}

		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)
		model.loading = false

		cmd := model.Refresh()
		assert.True(t, model.loading)
		assert.NotNil(t, cmd)
	})
}

func TestSignersModel_SetSize(t *testing.T) {
	t.Run("sets width and height", func(t *testing.T) {
		mockClient := client.NewMockClient()
		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)

		model.SetSize(100, 50)
		assert.Equal(t, 100, model.width)
		assert.Equal(t, 50, model.height)
	})
}

func TestSignersModel_Init(t *testing.T) {
	t.Run("returns batch command", func(t *testing.T) {
		mockClient := client.NewMockClient()
		mockClient.ListSignersFunc = func(ctx context.Context, filter *client.ListSignersFilter) (*client.ListSignersResponse, error) {
			time.Sleep(10 * time.Millisecond) // Simulate async operation
			return &client.ListSignersResponse{Signers: []client.Signer{}, Total: 0}, nil
		}

		model, err := NewSignersModel(mockClient, context.Background())
		require.NoError(t, err)

		cmd := model.Init()
		assert.NotNil(t, cmd)
	})
}
