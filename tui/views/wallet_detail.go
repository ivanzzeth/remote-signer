package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// WalletDetailModel represents the wallet detail view.
type WalletDetailModel struct {
	signers_svc   evm.SignerAPI
	hdwallets_svc evm.HDWalletAPI
	ctx           context.Context
	width         int
	height        int
	spinner       spinner.Model
	loading       bool
	err           error
	walletID      string
	wallet        *evm.Wallet // wallet metadata from list
	basePath      string      // for HD wallets
	signers       []evm.Signer
	selectedIdx   int
	goBack        bool
	actionResult  string
}

// WalletDetailDataMsg is sent when wallet detail data is loaded.
type WalletDetailDataMsg struct {
	Wallet  *evm.Wallet
	Signers []evm.Signer
	Err     error
}

// NewWalletDetailModel creates a new wallet detail model.
func NewWalletDetailModel(c *client.Client, ctx context.Context) (*WalletDetailModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newWalletDetailModelFromService(c.EVM.Signers, c.EVM.HDWallets, ctx)
}

// newWalletDetailModelFromService creates a wallet detail model from service (for testing).
func newWalletDetailModelFromService(svc evm.SignerAPI, hdSvc evm.HDWalletAPI, ctx context.Context) (*WalletDetailModel, error) {
	if svc == nil {
		return nil, fmt.Errorf("signer service is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	return &WalletDetailModel{
		signers_svc:   svc,
		hdwallets_svc: hdSvc,
		ctx:           ctx,
		spinner:       s,
	}, nil
}

// Init initializes the view.
func (m *WalletDetailModel) Init() tea.Cmd {
	return nil
}

// SetSize sets the view size.
func (m *WalletDetailModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// LoadWallet loads a wallet's signers. Pass the wallet from the list.
func (m *WalletDetailModel) LoadWallet(w evm.Wallet) tea.Cmd {
	if w.WalletID == "" {
		return nil
	}
	m.loading = true
	m.walletID = w.WalletID
	m.wallet = &w
	m.signers = nil
	m.goBack = false
	m.actionResult = ""
	m.selectedIdx = 0

	return tea.Batch(
		m.spinner.Tick,
		m.loadWalletData(),
	)
}

// ShouldGoBack returns true if the view should go back to the list.
func (m *WalletDetailModel) ShouldGoBack() bool {
	return m.goBack
}

// ResetGoBack resets the go back flag.
func (m *WalletDetailModel) ResetGoBack() {
	m.goBack = false
}

func (m *WalletDetailModel) loadWalletData() tea.Cmd {
	return func() tea.Msg {
		// Fetch signers
		resp, err := m.signers_svc.ListWalletSigners(m.ctx, m.walletID, nil)
		if err != nil {
			return WalletDetailDataMsg{
				Wallet: m.wallet,
				Err:    err,
			}
		}

		// If HD wallet, fetch base path
		var basePath string
		if m.wallet != nil && m.wallet.WalletType == "hd_wallet" && m.hdwallets_svc != nil {
			hdResp, err := m.hdwallets_svc.List(m.ctx)
			if err == nil && hdResp != nil {
				for _, hw := range hdResp.Wallets {
					if hw.PrimaryAddress == m.wallet.PrimaryAddress {
						basePath = hw.BasePath
						break
					}
				}
			}
		}

		m.basePath = basePath
		return WalletDetailDataMsg{
			Wallet:  m.wallet,
			Signers: resp.Signers,
		}
	}
}

// IsCapturingInput returns true if the view is capturing input.
func (m *WalletDetailModel) IsCapturingInput() bool {
	return false
}

// Update handles messages.
func (m *WalletDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case WalletDetailDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.wallet = msg.Wallet
			m.signers = msg.Signers
			m.err = nil
			m.actionResult = ""
		}
		return m, nil

	case spinner.TickMsg:
		if m.loading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case tea.KeyMsg:
		if m.loading {
			return m, nil
		}

		switch msg.String() {
		case "esc", "q", "backspace":
			m.goBack = true
			return m, nil
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "down", "j":
			if len(m.signers) > 0 && m.selectedIdx < len(m.signers)-1 {
				m.selectedIdx++
			}
		case "r":
			m.loading = true
			return m, tea.Batch(m.spinner.Tick, m.loadWalletData())
		}
	}

	return m, nil
}

// View renders the view.
func (m *WalletDetailModel) View() string {
	if m.loading {
		return fmt.Sprintf("\n%s Loading wallet details...\n", m.spinner.View())
	}

	var content strings.Builder

	// Header
	title := fmt.Sprintf("Wallet Detail: %s", m.walletID)
	content.WriteString(styles.TitleStyle.Render(title))
	content.WriteString("\n\n")

	// Action result
	if m.actionResult != "" {
		content.WriteString(m.actionResult)
		content.WriteString("\n\n")
	}

	// Wallet metadata
	if m.wallet != nil {
		content.WriteString(styles.SubtitleStyle.Render("Wallet Information"))
		content.WriteString("\n\n")
		content.WriteString(fmt.Sprintf("%-20s %s\n", "Wallet ID:", m.wallet.WalletID))
		content.WriteString(fmt.Sprintf("%-20s %s\n", "Type:", m.wallet.WalletType))
		content.WriteString(fmt.Sprintf("%-20s %d\n", "Signer Count:", m.wallet.SignerCount))

		enabled := "Yes"
		if !m.wallet.Enabled {
			enabled = "No"
		}
		content.WriteString(fmt.Sprintf("%-20s %s\n", "Enabled:", enabled))

		locked := "No"
		if m.wallet.Locked {
			locked = "Yes"
		}
		content.WriteString(fmt.Sprintf("%-20s %s\n", "Locked:", locked))
		content.WriteString("\n")
	}

	// Signers list
	content.WriteString(styles.SubtitleStyle.Render(fmt.Sprintf("Signers (%d)", len(m.signers))))
	content.WriteString("\n\n")

	if len(m.signers) == 0 {
		content.WriteString(styles.MutedColor.Render("  No signers found in this wallet"))
	} else {
		isHDWallet := m.wallet != nil && m.wallet.WalletType == "hd_wallet"

		// Table header
		var headerRow string
		if isHDWallet {
			headerRow = fmt.Sprintf("%-6s  %-44s  %-14s  %-14s  %-8s  %-60s",
				"INDEX", "ADDRESS", "TYPE", "STATUS", "ENABLED", "PATH")
		} else {
			headerRow = fmt.Sprintf("%-44s  %-14s  %-14s  %-8s",
				"ADDRESS", "TYPE", "STATUS", "ENABLED")
		}
		content.WriteString(styles.TableHeaderStyle.Render(headerRow))
		content.WriteString("\n")

		// Rows
		for i, s := range m.signers {
			selected := i == m.selectedIdx
			row := m.renderSignerRow(s, selected, isHDWallet)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	// Help
	content.WriteString("\n\n")
	helpText := "↑/↓: navigate | r: refresh | Esc/q: back"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *WalletDetailModel) renderSignerRow(s evm.Signer, selected bool, isHDWallet bool) string {
	addr := s.Address
	if len(addr) > 42 {
		addr = addr[:42]
	}

	signerType := s.Type
	status := "Unlocked"
	if s.Locked {
		status = "Locked"
	}
	enabled := "Yes"
	if !s.Enabled {
		enabled = "No"
	}

	var row string
	if isHDWallet {
		// For HD wallet: INDEX | ADDRESS | TYPE | STATUS | ENABLED | PATH
		index := "-"
		path := "-"
		if s.HDDerivationIndex != nil {
			index = fmt.Sprintf("%d", *s.HDDerivationIndex)
			// Construct full path
			if m.basePath != "" {
				path = fmt.Sprintf("%s/%d", m.basePath, *s.HDDerivationIndex)
			} else {
				// Fallback to generic Ethereum path
				path = fmt.Sprintf("m/44'/60'/0'/0/%d", *s.HDDerivationIndex)
			}
		}
		row = fmt.Sprintf("%-6s  %-44s  %-14s  %-14s  %-8s  %-60s",
			index, addr, signerType, status, enabled, path)
	} else {
		row = fmt.Sprintf("%-44s  %-14s  %-14s  %-8s",
			addr, signerType, status, enabled)
	}

	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}
	return styles.TableRowStyle.Render(row)
}
