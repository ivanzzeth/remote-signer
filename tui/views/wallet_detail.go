package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// WalletDetailModel represents the wallet detail view.
type WalletDetailModel struct {
	signers_svc     evm.SignerAPI
	hdwallets_svc   evm.HDWalletAPI
	collections_svc evm.CollectionAPI
	ctx             context.Context
	width           int
	height          int
	spinner         spinner.Model
	loading         bool
	err             error
	walletID        string
	wallet          *evm.Wallet // wallet metadata from list
	basePath        string      // for HD wallets
	signers         []evm.Signer
	members         []evm.CollectionMember // for collection wallets
	selectedIdx     int
	goBack          bool
	actionResult    string

	// Navigation: open a member wallet from collection detail
	openMemberWallet string

	// Collection member management
	showAddMember    bool
	addMemberInput   textinput.Model
	showRemoveConfirm bool
}

// WalletDetailDataMsg is sent when wallet detail data is loaded.
type WalletDetailDataMsg struct {
	Wallet   *evm.Wallet
	Signers  []evm.Signer
	Members  []evm.CollectionMember // for collection wallets
	BasePath string                 // for HD wallets
	Err      error
}

// WalletDetailActionMsg is sent after an add/remove member action completes.
type WalletDetailActionMsg struct {
	Success bool
	Message string
	Err     error
}

// NewWalletDetailModel creates a new wallet detail model.
func NewWalletDetailModel(c *client.Client, ctx context.Context) (*WalletDetailModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newWalletDetailModelFromService(c.EVM.Signers, c.EVM.HDWallets, c.EVM.Collections, ctx)
}

// newWalletDetailModelFromService creates a wallet detail model from service (for testing).
func newWalletDetailModelFromService(svc evm.SignerAPI, hdSvc evm.HDWalletAPI, colSvc evm.CollectionAPI, ctx context.Context) (*WalletDetailModel, error) {
	if svc == nil {
		return nil, fmt.Errorf("signer service is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	addInput := textinput.New()
	addInput.Placeholder = "Enter wallet ID to add..."
	addInput.Width = 50

	return &WalletDetailModel{
		signers_svc:     svc,
		hdwallets_svc:   hdSvc,
		collections_svc: colSvc,
		ctx:             ctx,
		spinner:         s,
		addMemberInput:  addInput,
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
	m.members = nil
	m.basePath = ""
	m.goBack = false
	m.actionResult = ""
	m.selectedIdx = 0
	m.openMemberWallet = ""

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
		// For collection wallets, load members instead of signers
		if m.wallet != nil && m.wallet.WalletType == "collection" && m.collections_svc != nil {
			membersResp, err := m.collections_svc.ListMembers(m.ctx, m.walletID)
			if err != nil {
				return WalletDetailDataMsg{Wallet: m.wallet, Err: err}
			}
			return WalletDetailDataMsg{
				Wallet:  m.wallet,
				Members: membersResp.Members,
			}
		}

		// Fetch signers for keystore and HD wallet types
		resp, err := m.signers_svc.ListWalletSigners(m.ctx, m.walletID, nil)
		if err != nil {
			return WalletDetailDataMsg{Wallet: m.wallet, Err: err}
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

		return WalletDetailDataMsg{
			Wallet:   m.wallet,
			Signers:  resp.Signers,
			BasePath: basePath,
		}
	}
}

// isCollection returns true if the current wallet is a collection type.
func (m *WalletDetailModel) isCollection() bool {
	return m.wallet != nil && m.wallet.WalletType == "collection"
}

// ShouldOpenMember returns true if the user selected a collection member to view.
func (m *WalletDetailModel) ShouldOpenMember() bool {
	return m.openMemberWallet != ""
}

// GetOpenMemberWalletID returns the wallet ID of the member to open and resets the flag.
func (m *WalletDetailModel) GetOpenMemberWalletID() string {
	id := m.openMemberWallet
	m.openMemberWallet = ""
	return id
}

// IsCapturingInput returns true if the view is capturing input.
func (m *WalletDetailModel) IsCapturingInput() bool {
	return m.showAddMember || m.showRemoveConfirm
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
			m.members = msg.Members
			m.basePath = msg.BasePath
			m.err = nil
			m.actionResult = ""
		}
		return m, nil

	case WalletDetailActionMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
		}
		// Reload data after action
		return m, tea.Batch(m.spinner.Tick, m.loadWalletData())

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

		// Handle add member input form
		if m.showAddMember {
			return m.handleAddMemberInput(msg)
		}

		// Handle remove confirm
		if m.showRemoveConfirm {
			return m.handleRemoveConfirm(msg)
		}

		listLen := len(m.signers)
		if m.isCollection() {
			listLen = len(m.members)
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
			if listLen > 0 && m.selectedIdx < listLen-1 {
				m.selectedIdx++
			}
		case "enter":
			// For collections, Enter opens the member wallet detail
			if m.isCollection() && m.selectedIdx < len(m.members) {
				m.openMemberWallet = m.members[m.selectedIdx].WalletID
			}
		case "a":
			// Add member (collections only)
			if m.isCollection() && m.collections_svc != nil {
				m.showAddMember = true
				m.addMemberInput.Reset()
				m.addMemberInput.Focus()
			}
		case "d":
			// Remove member (collections only)
			if m.isCollection() && m.collections_svc != nil && m.selectedIdx < len(m.members) {
				m.showRemoveConfirm = true
			}
		case "r":
			m.loading = true
			return m, tea.Batch(m.spinner.Tick, m.loadWalletData())
		}
	}

	return m, nil
}

func (m *WalletDetailModel) handleAddMemberInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.showAddMember = false
		m.addMemberInput.Blur()
		return m, nil
	case "enter":
		walletID := strings.TrimSpace(m.addMemberInput.Value())
		if walletID == "" {
			m.actionResult = styles.ErrorStyle.Render("Wallet ID cannot be empty")
			m.showAddMember = false
			m.addMemberInput.Blur()
			return m, nil
		}
		m.showAddMember = false
		m.addMemberInput.Blur()
		m.loading = true
		return m, m.addCollectionMember(walletID)
	}

	var cmd tea.Cmd
	m.addMemberInput, cmd = m.addMemberInput.Update(msg)
	return m, cmd
}

func (m *WalletDetailModel) handleRemoveConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		m.showRemoveConfirm = false
		if m.selectedIdx < len(m.members) {
			walletID := m.members[m.selectedIdx].WalletID
			m.loading = true
			return m, m.removeCollectionMember(walletID)
		}
	case "n", "N", "esc":
		m.showRemoveConfirm = false
	}
	return m, nil
}

func (m *WalletDetailModel) addCollectionMember(walletID string) tea.Cmd {
	return func() tea.Msg {
		req := &evm.AddCollectionMemberRequest{WalletID: walletID}
		_, err := m.collections_svc.AddMember(m.ctx, m.walletID, req)
		if err != nil {
			return WalletDetailActionMsg{Err: err}
		}
		return WalletDetailActionMsg{Success: true, Message: fmt.Sprintf("Added member %s", walletID)}
	}
}

func (m *WalletDetailModel) removeCollectionMember(walletID string) tea.Cmd {
	return func() tea.Msg {
		err := m.collections_svc.RemoveMember(m.ctx, m.walletID, walletID)
		if err != nil {
			return WalletDetailActionMsg{Err: err}
		}
		return WalletDetailActionMsg{Success: true, Message: fmt.Sprintf("Removed member %s", walletID)}
	}
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

	if m.isCollection() {
		// Show add member form if active
		if m.showAddMember {
			content.WriteString(styles.SubtitleStyle.Render("Add Member"))
			content.WriteString("\n\n")
			content.WriteString("  " + m.addMemberInput.View() + "\n\n")
			content.WriteString(styles.HelpStyle.Render("  Enter: confirm | Esc: cancel"))
			return content.String()
		}

		// Show remove confirm if active
		if m.showRemoveConfirm && m.selectedIdx < len(m.members) {
			content.WriteString(styles.WarningStyle.Render(
				fmt.Sprintf("Remove member %s? (y/n)", m.members[m.selectedIdx].WalletID)))
			content.WriteString("\n\n")
			content.WriteString(styles.HelpStyle.Render("  y: confirm | n/Esc: cancel"))
			return content.String()
		}

		// Collection: show members (wallets)
		content.WriteString(styles.SubtitleStyle.Render(fmt.Sprintf("Members (%d)", len(m.members))))
		content.WriteString("\n\n")

		if len(m.members) == 0 {
			content.WriteString(styles.MutedColor.Render("  No members in this collection"))
		} else {
			headerRow := fmt.Sprintf("%-44s  %-14s  %-20s", "WALLET ID", "TYPE", "ADDED AT")
			content.WriteString(styles.TableHeaderStyle.Render(headerRow))
			content.WriteString("\n")

			for i, member := range m.members {
				selected := i == m.selectedIdx
				row := fmt.Sprintf("%-44s  %-14s  %-20s",
					truncate(member.WalletID, 42),
					member.WalletType,
					member.AddedAt.Format("2006-01-02 15:04"),
				)
				if selected {
					content.WriteString(styles.TableSelectedRowStyle.Render(row))
				} else {
					content.WriteString(styles.TableRowStyle.Render(row))
				}
				content.WriteString("\n")
			}
		}

		content.WriteString("\n\n")
		helpText := "↑/↓: navigate | Enter: open member | a: add | d: remove | r: refresh | Esc/q: back"
		content.WriteString(styles.HelpStyle.Render(helpText))
	} else {
		// Keystore / HD Wallet: show signers
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

		content.WriteString("\n\n")
		helpText := "↑/↓: navigate | r: refresh | Esc/q: back"
		content.WriteString(styles.HelpStyle.Render(helpText))
	}

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
