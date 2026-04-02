package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// WalletsModel represents the wallets list view.
type WalletsModel struct {
	signersSvc  evm.SignerAPI
	ctx         context.Context
	width       int
	height      int
	spinner     spinner.Model
	loading     bool
	err         error
	wallets     []evm.Wallet
	selectedIdx int
	tagFilter   string
	showFilter  bool
	filterInput textinput.Model

	// Navigation to detail view
	goDetail       bool
	selectedWallet string
}

// WalletsDataMsg is sent when wallets data is loaded.
type WalletsDataMsg struct {
	Wallets []evm.Wallet
	Err     error
}

// NewWalletsModel creates a new wallets model.
func NewWalletsModel(c *client.Client, ctx context.Context) (*WalletsModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	filterInput := textinput.New()
	filterInput.Placeholder = "Filter by tag..."
	filterInput.Width = 40

	return &WalletsModel{
		signersSvc:  c.EVM.Signers,
		ctx:         ctx,
		spinner:     s,
		loading:     true,
		filterInput: filterInput,
	}, nil
}

// Init initializes the wallets model.
func (m *WalletsModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.fetchWallets)
}

// Update handles messages for the wallets model.
func (m *WalletsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		if m.showFilter {
			return m.handleFilterInput(msg)
		}

		switch msg.String() {
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "down", "j":
			if m.selectedIdx < len(m.wallets)-1 {
				m.selectedIdx++
			}
		case "enter":
			if len(m.wallets) > 0 && m.selectedIdx < len(m.wallets) {
				m.goDetail = true
				m.selectedWallet = m.wallets[m.selectedIdx].WalletID
			}
		case "f":
			m.showFilter = true
			m.filterInput.Focus()
		case "r":
			m.loading = true
			return m, tea.Batch(m.spinner.Tick, m.fetchWallets)
		}

	case WalletsDataMsg:
		m.loading = false
		m.err = msg.Err
		if msg.Err == nil {
			m.wallets = msg.Wallets
			if m.selectedIdx >= len(m.wallets) {
				m.selectedIdx = 0
			}
		}

	case spinner.TickMsg:
		if m.loading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// handleFilterInput handles filter input mode.
func (m *WalletsModel) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.String() {
	case "esc":
		m.showFilter = false
		m.filterInput.Blur()
		return m, nil
	case "enter":
		m.tagFilter = m.filterInput.Value()
		m.showFilter = false
		m.filterInput.Blur()
		m.loading = true
		return m, tea.Batch(m.spinner.Tick, m.fetchWallets)
	}

	m.filterInput, cmd = m.filterInput.Update(msg)
	return m, cmd
}

// View renders the wallets view.
func (m *WalletsModel) View() string {
	if m.loading {
		return fmt.Sprintf("\n  %s Loading wallets...", m.spinner.View())
	}

	if m.err != nil {
		return fmt.Sprintf("\n  Error: %v\n\n  Press 'r' to retry", m.err)
	}

	if m.showFilter {
		return m.renderFilterInput()
	}

	return m.renderWalletsList()
}

// renderFilterInput renders the filter input form.
func (m *WalletsModel) renderFilterInput() string {
	var b strings.Builder

	b.WriteString(styles.TitleStyle.Render("Filter Wallets by Tag") + "\n\n")
	b.WriteString("  " + m.filterInput.View() + "\n\n")
	b.WriteString(styles.HelpStyle.Render("  enter: apply filter • esc: cancel"))

	return b.String()
}

// renderWalletsList renders the wallets list.
func (m *WalletsModel) renderWalletsList() string {
	var b strings.Builder

	title := "Wallets"
	if m.tagFilter != "" {
		title += fmt.Sprintf(" (tag: %s)", m.tagFilter)
	}
	b.WriteString(styles.TitleStyle.Render(title) + "\n\n")

	if len(m.wallets) == 0 {
		b.WriteString("  No wallets found\n")
		return b.String()
	}

	// Table header
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	b.WriteString(headerStyle.Render(fmt.Sprintf(
		"  %-44s %-12s %-8s %-8s %-8s\n",
		"WALLET ID",
		"TYPE",
		"SIGNERS",
		"ENABLED",
		"LOCKED",
	)))
	b.WriteString(strings.Repeat("─", m.width) + "\n")

	// Table rows
	for i, w := range m.wallets {
		enabled := "✗"
		if w.Enabled {
			enabled = "✓"
		}
		locked := "✗"
		if w.Locked {
			locked = "✓"
		}

		displayName := w.DisplayName
		if displayName == "" {
			displayName = truncate(w.WalletID, 40)
		} else {
			displayName = truncate(displayName, 40)
		}

		rowStyle := lipgloss.NewStyle()
		if i == m.selectedIdx {
			rowStyle = rowStyle.Background(lipgloss.Color("240"))
		}

		row := fmt.Sprintf(
			"  %-44s %-12s %-8d %-8s %-8s",
			displayName,
			w.WalletType,
			w.SignerCount,
			enabled,
			locked,
		)

		b.WriteString(rowStyle.Render(row) + "\n")

		// Show tags if present
		if len(w.Tags) > 0 {
			tagsStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
			tagsStr := "    Tags: " + strings.Join(w.Tags, ", ")
			b.WriteString(tagsStyle.Render(tagsStr) + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(styles.HelpStyle.Render(
		"  ↑/k up • ↓/j down • enter: details • f: filter • r: refresh • q: quit",
	))

	return b.String()
}

// fetchWallets fetches wallets from the API.
func (m *WalletsModel) fetchWallets() tea.Msg {
	filter := &evm.ListSignersFilter{}
	if m.tagFilter != "" {
		filter.Tag = m.tagFilter
	}

	resp, err := m.signersSvc.ListWallets(m.ctx, filter)
	if err != nil {
		return WalletsDataMsg{Err: err}
	}

	return WalletsDataMsg{
		Wallets: resp.Wallets,
		Err:     nil,
	}
}

// SetSize sets the size of the view.
func (m *WalletsModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// ShouldShowDetail returns true if the user selected a wallet to view details.
func (m *WalletsModel) ShouldShowDetail() bool {
	return m.goDetail
}

// SelectedWallet returns the selected wallet ID.
func (m *WalletsModel) SelectedWallet() string {
	return m.selectedWallet
}

// GetSelectedWallet returns the selected wallet object for detail view.
func (m *WalletsModel) GetSelectedWallet() evm.Wallet {
	for _, w := range m.wallets {
		if w.WalletID == m.selectedWallet {
			return w
		}
	}
	return evm.Wallet{WalletID: m.selectedWallet}
}

// ClearDetailFlag clears the go-to-detail flag.
func (m *WalletsModel) ClearDetailFlag() {
	m.goDetail = false
	m.selectedWallet = ""
}

// Refresh reloads the wallets list.
func (m *WalletsModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(m.spinner.Tick, m.fetchWallets)
}

// IsCapturingInput returns true if the view is capturing input.
func (m *WalletsModel) IsCapturingInput() bool {
	return m.showFilter
}

// truncate truncates a string to the specified length.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
