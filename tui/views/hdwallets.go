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

// HDWalletsModel represents the HD wallets list view.
type HDWalletsModel struct {
	hdwallets_svc evm.HDWalletAPI
	signers_svc   evm.SignerAPI // for unlock (uses signer API with primary address)
	ctx           context.Context
	width         int
	height        int
	spinner       spinner.Model
	loading       bool
	err           error
	wallets       []evm.HDWalletResponse
	selectedIdx   int
	actionResult  string

	// Navigation to detail view
	goDetail         bool
	selectedPrimAddr string

	// Create/import form state
	showCreate    bool
	createMode    string // "create" or "import"
	createStep    int    // create: 0=entropy, 1=password, 2=confirm; import: 0=mnemonic, 1=password, 2=confirm
	entropyIdx    int    // 0=128-bit, 1=256-bit
	entropyBits   int    // 128 or 256
	mnemonicInput textinput.Model
	passwordInput textinput.Model
	confirmInput  textinput.Model
	showPassword  bool

	// Unlock form state (for locked HD wallets)
	showUnlock  bool
	unlockInput textinput.Model
}

// HDWalletsDataMsg is sent when HD wallets data is loaded.
type HDWalletsDataMsg struct {
	Wallets []evm.HDWalletResponse
	Err     error
}

// HDWalletCreateMsg is sent when an HD wallet is created or imported.
type HDWalletCreateMsg struct {
	Wallet  *evm.HDWalletResponse
	Success bool
	Message string
	Err     error
}

// HDWalletUnlockMsg is sent when an HD wallet unlock completes.
type HDWalletUnlockMsg struct {
	PrimaryAddr string
	Success    bool
	Message    string
	Err        error
}

// NewHDWalletsModel creates a new HD wallets model.
func NewHDWalletsModel(c *client.Client, ctx context.Context) (*HDWalletsModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newHDWalletsModelFromService(c.EVM.HDWallets, c.EVM.Signers, ctx)
}

// newHDWalletsModelFromService creates an HD wallets model from services (for testing, signers_svc may be nil).
func newHDWalletsModelFromService(hdSvc evm.HDWalletAPI, signersSvc evm.SignerAPI, ctx context.Context) (*HDWalletsModel, error) {
	if hdSvc == nil {
		return nil, fmt.Errorf("HD wallet service is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	mnInput := textinput.New()
	mnInput.Placeholder = "Enter mnemonic phrase"
	mnInput.Width = 60
	// Mask mnemonic like password: TUI must never show plaintext mnemonic or private key.
	mnInput.EchoMode = textinput.EchoPassword

	pwInput := textinput.New()
	pwInput.Placeholder = "Enter password"
	pwInput.Width = 40
	pwInput.EchoMode = textinput.EchoPassword

	confirmInput := textinput.New()
	confirmInput.Placeholder = "Confirm password"
	confirmInput.Width = 40
	confirmInput.EchoMode = textinput.EchoPassword

	unlockInput := textinput.New()
	unlockInput.Placeholder = "Enter password to unlock"
	unlockInput.Width = 40
	unlockInput.EchoMode = textinput.EchoPassword

	return &HDWalletsModel{
		hdwallets_svc: hdSvc,
		signers_svc:   signersSvc,
		ctx:           ctx,
		spinner:       s,
		loading:       true,
		entropyBits:   256,
		mnemonicInput: mnInput,
		passwordInput: pwInput,
		confirmInput:  confirmInput,
		unlockInput:   unlockInput,
	}, nil
}

// Init initializes the HD wallets view.
func (m *HDWalletsModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size.
func (m *HDWalletsModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh refreshes the HD wallets data.
func (m *HDWalletsModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// GetSelectedPrimaryAddr returns the selected wallet's primary address.
func (m *HDWalletsModel) GetSelectedPrimaryAddr() string {
	if m.selectedIdx >= 0 && m.selectedIdx < len(m.wallets) {
		return m.wallets[m.selectedIdx].PrimaryAddress
	}
	return ""
}

// ShouldOpenDetail returns true if the view should navigate to detail.
func (m *HDWalletsModel) ShouldOpenDetail() bool {
	return m.goDetail
}

// ResetOpenDetail resets the detail navigation flag.
func (m *HDWalletsModel) ResetOpenDetail() {
	m.goDetail = false
}

func (m *HDWalletsModel) loadData() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.hdwallets_svc.List(m.ctx)
		if err != nil {
			return HDWalletsDataMsg{Err: err}
		}
		return HDWalletsDataMsg{Wallets: resp.Wallets, Err: nil}
	}
}

func (m *HDWalletsModel) createWallet(password string, entropyBits int) tea.Cmd {
	return func() tea.Msg {
		req := &evm.CreateHDWalletRequest{
			Action:      "create",
			Password:    password,
			EntropyBits: entropyBits,
		}
		wallet, err := m.hdwallets_svc.Create(m.ctx, req)
		if err != nil {
			return HDWalletCreateMsg{Success: false, Err: err}
		}
		return HDWalletCreateMsg{
			Wallet:  wallet,
			Success: true,
			Message: fmt.Sprintf("HD wallet created: %s", wallet.PrimaryAddress),
		}
	}
}

func (m *HDWalletsModel) importWallet(mnemonic, password string) tea.Cmd {
	return func() tea.Msg {
		req := &evm.CreateHDWalletRequest{
			Action:   "import",
			Password: password,
			Mnemonic: mnemonic,
		}
		wallet, err := m.hdwallets_svc.Import(m.ctx, req)
		if err != nil {
			return HDWalletCreateMsg{Success: false, Err: err}
		}
		return HDWalletCreateMsg{
			Wallet:  wallet,
			Success: true,
			Message: fmt.Sprintf("HD wallet imported: %s", wallet.PrimaryAddress),
		}
	}
}

func (m *HDWalletsModel) unlockWallet(primaryAddr, password string) tea.Cmd {
	return func() tea.Msg {
		if m.signers_svc == nil {
			return HDWalletUnlockMsg{PrimaryAddr: primaryAddr, Success: false, Err: fmt.Errorf("unlock not available")}
		}
		req := &evm.UnlockSignerRequest{Password: password}
		resp, err := m.signers_svc.Unlock(m.ctx, primaryAddr, req)
		if err != nil {
			return HDWalletUnlockMsg{PrimaryAddr: primaryAddr, Success: false, Err: err}
		}
		return HDWalletUnlockMsg{
			PrimaryAddr: primaryAddr,
			Success:     true,
			Message:     fmt.Sprintf("HD wallet unlocked: %s", resp.Address),
		}
	}
}

// Update handles messages.
func (m *HDWalletsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case HDWalletsDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.wallets = msg.Wallets
			m.err = nil
		}
		return m, nil

	case HDWalletCreateMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.resetCreateForm()
			return m, m.Refresh()
		}
		return m, nil

	case HDWalletUnlockMsg:
		m.loading = false
		m.showUnlock = false
		m.unlockInput.SetValue("")
		m.unlockInput.Blur()
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Unlock failed: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			return m, m.Refresh()
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
		if m.showUnlock {
			return m.handleUnlockInput(msg)
		}
		if m.showCreate {
			return m.handleCreateInput(msg)
		}

		switch msg.String() {
		case "r":
			return m, m.Refresh()
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.selectedIdx < len(m.wallets)-1 {
				m.selectedIdx++
			}
			return m, nil
		case "enter":
			if len(m.wallets) > 0 && m.selectedIdx < len(m.wallets) {
				m.goDetail = true
				m.selectedPrimAddr = m.wallets[m.selectedIdx].PrimaryAddress
			}
			return m, nil
		case "u":
			// Unlock selected locked HD wallet
			if m.signers_svc != nil && len(m.wallets) > 0 && m.selectedIdx < len(m.wallets) {
				wallet := m.wallets[m.selectedIdx]
				if wallet.Locked {
					m.showUnlock = true
					m.unlockInput.SetValue("")
					m.unlockInput.Focus()
					return m, textinput.Blink
				}
			}
			return m, nil
		case "c":
			m.showCreate = true
			m.createMode = "create"
			m.createStep = 0
			m.entropyIdx = 1 // default to 256-bit
			m.entropyBits = 256
			m.actionResult = ""
			return m, nil
		case "i":
			m.showCreate = true
			m.createMode = "import"
			m.createStep = 0
			m.actionResult = ""
			m.mnemonicInput.Focus()
			return m, textinput.Blink
		}
	}

	return m, nil
}

func (m *HDWalletsModel) handleUnlockInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.unlockInput.Value() != "" && len(m.wallets) > 0 && m.selectedIdx < len(m.wallets) {
			wallet := m.wallets[m.selectedIdx]
			if wallet.Locked {
				password := m.unlockInput.Value()
				m.loading = true
				m.unlockInput.Blur()
				return m, tea.Batch(m.spinner.Tick, m.unlockWallet(wallet.PrimaryAddress, password))
			}
		}
		return m, nil
	case "esc":
		m.showUnlock = false
		m.unlockInput.SetValue("")
		m.unlockInput.Blur()
		return m, nil
	default:
		var cmd tea.Cmd
		m.unlockInput, cmd = m.unlockInput.Update(msg)
		return m, cmd
	}
}

func (m *HDWalletsModel) handleCreateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.createMode == "create" {
		return m.handleCreateWalletInput(msg)
	}
	return m.handleImportWalletInput(msg)
}

func (m *HDWalletsModel) handleCreateWalletInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.createStep {
	case 0: // Select entropy
		switch msg.String() {
		case "up", "k":
			if m.entropyIdx > 0 {
				m.entropyIdx--
			}
			return m, nil
		case "down", "j":
			if m.entropyIdx < 1 {
				m.entropyIdx++
			}
			return m, nil
		case "enter":
			if m.entropyIdx == 0 {
				m.entropyBits = 128
			} else {
				m.entropyBits = 256
			}
			m.createStep = 1
			m.passwordInput.Focus()
			return m, textinput.Blink
		case "esc":
			m.resetCreateForm()
			return m, nil
		}
	case 1: // Password
		return m.handlePasswordStep(msg)
	case 2: // Confirm
		return m.handleConfirmStep(msg)
	}
	return m, nil
}

func (m *HDWalletsModel) handleImportWalletInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.createStep {
	case 0: // Mnemonic
		switch msg.String() {
		case "enter":
			if m.mnemonicInput.Value() != "" {
				m.createStep = 1
				m.mnemonicInput.Blur()
				m.passwordInput.Focus()
				return m, textinput.Blink
			}
			return m, nil
		case "esc":
			m.resetCreateForm()
			return m, nil
		default:
			var cmd tea.Cmd
			m.mnemonicInput, cmd = m.mnemonicInput.Update(msg)
			return m, cmd
		}
	case 1: // Password
		return m.handlePasswordStep(msg)
	case 2: // Confirm
		return m.handleConfirmStep(msg)
	}
	return m, nil
}

func (m *HDWalletsModel) handlePasswordStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.passwordInput.Value() != "" {
			// Enforce same password strength as keystore create
			if errMsg, _ := validatePassword(m.passwordInput.Value()); errMsg != "" {
				m.actionResult = styles.ErrorStyle.Render(errMsg)
				return m, nil
			}
			m.actionResult = ""
			m.createStep = 2
			m.confirmInput.Focus()
			m.passwordInput.Blur()
			return m, textinput.Blink
		}
		return m, nil
	case "esc":
		m.resetCreateForm()
		return m, nil
	case "tab":
		m.showPassword = !m.showPassword
		if m.showPassword {
			m.passwordInput.EchoMode = textinput.EchoNormal
		} else {
			m.passwordInput.EchoMode = textinput.EchoPassword
		}
		return m, nil
	default:
		var cmd tea.Cmd
		m.passwordInput, cmd = m.passwordInput.Update(msg)
		return m, cmd
	}
}

func (m *HDWalletsModel) handleConfirmStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.confirmInput.Value() != m.passwordInput.Value() {
			m.actionResult = styles.ErrorStyle.Render("Passwords do not match")
			return m, nil
		}
		password := m.passwordInput.Value()
		if errMsg, _ := validatePassword(password); errMsg != "" {
			m.actionResult = styles.ErrorStyle.Render(errMsg)
			return m, nil
		}
		m.loading = true
		m.confirmInput.Blur()
		if m.createMode == "create" {
			return m, tea.Batch(m.spinner.Tick, m.createWallet(password, m.entropyBits))
		}
		mnemonic := m.mnemonicInput.Value()
		return m, tea.Batch(m.spinner.Tick, m.importWallet(mnemonic, password))
	case "esc":
		m.resetCreateForm()
		return m, nil
	case "tab":
		m.showPassword = !m.showPassword
		if m.showPassword {
			m.confirmInput.EchoMode = textinput.EchoNormal
		} else {
			m.confirmInput.EchoMode = textinput.EchoPassword
		}
		return m, nil
	default:
		var cmd tea.Cmd
		m.confirmInput, cmd = m.confirmInput.Update(msg)
		return m, cmd
	}
}

func (m *HDWalletsModel) resetCreateForm() {
	m.showCreate = false
	m.createStep = 0
	m.createMode = ""
	m.entropyIdx = 0
	m.showPassword = false
	m.mnemonicInput.SetValue("")
	m.mnemonicInput.Blur()
	m.passwordInput.SetValue("")
	m.passwordInput.Blur()
	m.passwordInput.EchoMode = textinput.EchoPassword
	m.confirmInput.SetValue("")
	m.confirmInput.Blur()
	m.confirmInput.EchoMode = textinput.EchoPassword
}

// View renders the HD wallets view.
func (m *HDWalletsModel) View() string {
	if m.showUnlock {
		return m.renderUnlockForm()
	}
	if m.showCreate {
		return m.renderCreateForm()
	}

	if m.loading {
		return m.renderLoading()
	}

	if m.err != nil {
		return m.renderError()
	}

	return m.renderWallets()
}

func (m *HDWalletsModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading HD wallets...", m.spinner.View()),
	)
}

func (m *HDWalletsModel) renderError() string {
	errBox := styles.BoxStyle.
		BorderForeground(styles.ErrorColor).
		Render(fmt.Sprintf("Error: %v\n\nPress 'r' to retry", m.err))

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		errBox,
	)
}

func (m *HDWalletsModel) renderCreateForm() string {
	var content strings.Builder

	if m.createMode == "create" {
		content.WriteString(styles.TitleStyle.Render("Create New HD Wallet"))
	} else {
		content.WriteString(styles.TitleStyle.Render("Import HD Wallet from Mnemonic"))
	}
	content.WriteString("\n\n")

	if m.createMode == "create" {
		m.renderCreateWalletForm(&content)
	} else {
		m.renderImportWalletForm(&content)
	}

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}

func (m *HDWalletsModel) renderCreateWalletForm(content *strings.Builder) {
	switch m.createStep {
	case 0:
		content.WriteString(styles.SubtitleStyle.Render("Select Entropy:"))
		content.WriteString("\n\n")
		options := []string{"128-bit", "256-bit (default)"}
		for i, opt := range options {
			if i == m.entropyIdx {
				content.WriteString(styles.TableSelectedRowStyle.Render("> " + opt))
			} else {
				content.WriteString(styles.TableRowStyle.Render("  " + opt))
			}
			content.WriteString("\n")
		}
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("up/down: select | Enter: confirm | Esc: cancel"))
	case 1:
		fmt.Fprintf(content, "Entropy: %s\n\n", styles.HighlightStyle.Render(fmt.Sprintf("%d-bit", m.entropyBits)))
		content.WriteString(styles.SubtitleStyle.Render("Enter Password:"))
		content.WriteString("\n\n")
		content.WriteString(m.passwordInput.View())
		content.WriteString("\n\n")
		m.renderPasswordHelp(content, "continue")
	case 2:
		fmt.Fprintf(content, "Entropy: %s\n\n", styles.HighlightStyle.Render(fmt.Sprintf("%d-bit", m.entropyBits)))
		content.WriteString(styles.SubtitleStyle.Render("Confirm Password:"))
		content.WriteString("\n\n")
		content.WriteString(m.confirmInput.View())
		content.WriteString("\n\n")
		if _, warnMsg := validatePassword(m.passwordInput.Value()); warnMsg != "" {
			content.WriteString(styles.WarningStyle.Render(warnMsg))
			content.WriteString("\n\n")
		}
		if m.actionResult != "" {
			content.WriteString(m.actionResult)
			content.WriteString("\n\n")
		}
		m.renderPasswordHelp(content, "create")
	}
}

func (m *HDWalletsModel) renderImportWalletForm(content *strings.Builder) {
	switch m.createStep {
	case 0:
		content.WriteString(styles.SubtitleStyle.Render("Enter Mnemonic:"))
		content.WriteString("\n\n")
		content.WriteString(m.mnemonicInput.View())
		content.WriteString("\n\n")
		content.WriteString(styles.MutedColor.Render("Enter: continue | Esc: cancel"))
	case 1:
		content.WriteString(styles.SubtitleStyle.Render("Enter Password:"))
		content.WriteString("\n\n")
		content.WriteString(m.passwordInput.View())
		content.WriteString("\n\n")
		m.renderPasswordHelp(content, "continue")
	case 2:
		content.WriteString(styles.SubtitleStyle.Render("Confirm Password:"))
		content.WriteString("\n\n")
		content.WriteString(m.confirmInput.View())
		content.WriteString("\n\n")
		if _, warnMsg := validatePassword(m.passwordInput.Value()); warnMsg != "" {
			content.WriteString(styles.WarningStyle.Render(warnMsg))
			content.WriteString("\n\n")
		}
		if m.actionResult != "" {
			content.WriteString(m.actionResult)
			content.WriteString("\n\n")
		}
		m.renderPasswordHelp(content, "import")
	}
}

func (m *HDWalletsModel) renderPasswordHelp(content *strings.Builder, action string) {
	if m.showPassword {
		content.WriteString(styles.MutedColor.Render(fmt.Sprintf("Tab: hide password | Enter: %s | Esc: cancel", action)))
	} else {
		content.WriteString(styles.MutedColor.Render(fmt.Sprintf("Tab: show password | Enter: %s | Esc: cancel", action)))
	}
}

func (m *HDWalletsModel) renderWallets() string {
	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("HD Wallets"))
	content.WriteString("\n\n")

	if m.actionResult != "" {
		content.WriteString(m.actionResult)
		content.WriteString("\n\n")
	}

	// Table header
	headerRow := fmt.Sprintf("%-44s  %-18s  %-8s  %-8s",
		"Primary Address", "Path", "Derived", "Status")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	if len(m.wallets) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No HD wallets found"))
	} else {
		for i, wallet := range m.wallets {
			row := m.renderWalletRow(wallet, i == m.selectedIdx)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	// Pagination info
	content.WriteString("\n")
	total := len(m.wallets)
	if total == 0 {
		content.WriteString(styles.MutedColor.Render("Showing 0 of 0"))
	} else {
		content.WriteString(styles.MutedColor.Render(fmt.Sprintf("Showing 1-%d of %d", total, total)))
	}

	// Help
	content.WriteString("\n\n")
	helpText := "up/down: navigate | Enter: details | u: unlock (locked) | c: create | i: import | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *HDWalletsModel) renderUnlockForm() string {
	var content strings.Builder
	content.WriteString(styles.TitleStyle.Render("Unlock HD Wallet"))
	content.WriteString("\n\n")
	if len(m.wallets) > 0 && m.selectedIdx < len(m.wallets) {
		content.WriteString(styles.SubtitleStyle.Render("Primary address: " + m.wallets[m.selectedIdx].PrimaryAddress))
		content.WriteString("\n\n")
	}
	content.WriteString(styles.SubtitleStyle.Render("Enter password:"))
	content.WriteString("\n\n")
	content.WriteString(m.unlockInput.View())
	content.WriteString("\n\n")
	content.WriteString(styles.MutedColor.Render("Enter: unlock | Esc: cancel"))

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}

// IsCapturingInput returns true when this view is capturing keyboard input (form active).
func (m *HDWalletsModel) IsCapturingInput() bool {
	return m.showCreate || m.showUnlock
}

func (m *HDWalletsModel) renderWalletRow(wallet evm.HDWalletResponse, selected bool) string {
	address := wallet.PrimaryAddress
	if len(address) > 44 {
		address = address[:41] + "..."
	}

	status := "Unlocked"
	if wallet.Locked {
		status = "Locked"
	}

	row := fmt.Sprintf("%-44s  %-18s  %-8d  %-8s",
		address,
		wallet.BasePath,
		wallet.DerivedCount,
		status,
	)

	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}

	return styles.TableRowStyle.Render(row)
}
