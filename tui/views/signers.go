package views

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

const (
	// maxUnlockAttempts is the maximum failed unlock attempts before cooldown.
	maxUnlockAttempts = 5
	// unlockCooldownDuration is how long to wait after max failed attempts.
	unlockCooldownDuration = 30 * time.Second
	// minPasswordLength is the minimum password length for keystore creation.
	minPasswordLength = 16
	// recommendedPasswordLength is the recommended password length.
	recommendedPasswordLength = 24
)

// validatePassword checks password complexity requirements.
// Returns an error message if invalid, or a warning message if valid but could be stronger.
// Returns ("", "") if fully compliant.
func validatePassword(pw string) (errMsg string, warnMsg string) {
	if len(pw) < minPasswordLength {
		return fmt.Sprintf("Password must be at least %d characters (currently %d)", minPasswordLength, len(pw)), ""
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, c := range pw {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	var missing []string
	if !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if !hasDigit {
		missing = append(missing, "digit")
	}
	if !hasSymbol {
		missing = append(missing, "symbol")
	}
	if len(missing) > 0 {
		return fmt.Sprintf("Password must include: %s", strings.Join(missing, ", ")), ""
	}

	if len(pw) < recommendedPasswordLength {
		return "", fmt.Sprintf("Tip: %d+ characters recommended for stronger security", recommendedPasswordLength)
	}
	return "", ""
}

// SignersModel represents the signers list view
type SignersModel struct {
	signers_svc evm.SignerAPI
	ctx         context.Context
	width       int
	height      int
	spinner     spinner.Model
	loading     bool
	err         error
	signers     []evm.Signer
	total       int
	hasMore     bool
	selectedIdx int
	offset      int
	limit       int
	typeFilter  string
	showFilter  bool
	filterInput textinput.Model

	// Unlock/lock signer state
	showUnlock         bool
	unlockInput        textinput.Model
	unlockAttempts     map[string]int       // address → failed attempt count
	unlockCooldownUtil map[string]time.Time // address → cooldown expiry

	// Create signer state
	showCreate       bool
	createStep       int // 0: select type, 1: enter password (keystore) or loading wallets (hd), 2: confirm (keystore) or pick wallet (hd), 3: enter index (hd)
	typeIdx          int // 0=keystore, 1=hd_wallet
	selectedType     string
	passwordInput    textinput.Model
	confirmInput     textinput.Model
	showPassword     bool
	actionResult     string

	// HD wallet derive state (in create flow)
	hdwallets_svc evm.HDWalletAPI
	hdWallets     []evm.HDWalletResponse
	hdWalletIdx   int
	indexInput    textinput.Model
}

// SignersDataMsg is sent when signers data is loaded
type SignersDataMsg struct {
	Signers []evm.Signer
	Total   int
	HasMore bool
	Err     error
}

// SignerCreateMsg is sent when a signer is created
type SignerCreateMsg struct {
	Signer  *evm.Signer
	Success bool
	Message string
	Err     error
}

// SignerHDWalletListMsg is sent when HD wallet list is loaded for the derive picker.
type SignerHDWalletListMsg struct {
	Wallets []evm.HDWalletResponse
	Err     error
}

// SignerUnlockMsg is sent when a signer unlock completes.
type SignerUnlockMsg struct {
	Address string // address attempted (for rate limiting)
	Signer  *evm.Signer
	Success bool
	Message string
	Err     error
}

// SignerLockMsg is sent when a signer lock completes.
type SignerLockMsg struct {
	Signer  *evm.Signer
	Success bool
	Message string
	Err     error
}

// SignerHDDeriveMsg is sent when an HD wallet derive completes in the signers flow.
type SignerHDDeriveMsg struct {
	Derived []evm.SignerInfo
	Success bool
	Message string
	Err     error
}

// NewSignersModel creates a new signers model
func NewSignersModel(c *client.Client, ctx context.Context) (*SignersModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newSignersModelFromService(c.EVM.Signers, c.EVM.HDWallets, ctx)
}

// newSignersModelFromService creates a signers model from a SignerAPI (for testing).
func newSignersModelFromService(svc evm.SignerAPI, hdSvc evm.HDWalletAPI, ctx context.Context) (*SignersModel, error) {
	if svc == nil {
		return nil, fmt.Errorf("client is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	ti := textinput.New()
	ti.Placeholder = "Filter value"
	ti.Width = 40

	pwInput := textinput.New()
	pwInput.Placeholder = "Enter password"
	pwInput.Width = 40
	pwInput.EchoMode = textinput.EchoPassword

	confirmInput := textinput.New()
	confirmInput.Placeholder = "Confirm password"
	confirmInput.Width = 40
	confirmInput.EchoMode = textinput.EchoPassword

	idxInput := textinput.New()
	idxInput.Placeholder = "Derivation index"
	idxInput.Width = 20

	unlockInput := textinput.New()
	unlockInput.Placeholder = "Enter password to unlock"
	unlockInput.Width = 40
	unlockInput.EchoMode = textinput.EchoPassword

	return &SignersModel{
		signers_svc:        svc,
		hdwallets_svc:      hdSvc,
		ctx:                ctx,
		spinner:            s,
		loading:            true,
		limit:              20,
		filterInput:        ti,
		passwordInput:      pwInput,
		confirmInput:       confirmInput,
		indexInput:         idxInput,
		unlockInput:        unlockInput,
		unlockAttempts:     make(map[string]int),
		unlockCooldownUtil: make(map[string]time.Time),
	}, nil
}

// Init initializes the signers view
func (m *SignersModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size
func (m *SignersModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh refreshes the signers data
func (m *SignersModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

func (m *SignersModel) loadData() tea.Cmd {
	return func() tea.Msg {
		filter := &evm.ListSignersFilter{
			Type:   m.typeFilter,
			Limit:  m.limit,
			Offset: m.offset,
		}

		resp, err := m.signers_svc.List(m.ctx, filter)
		if err != nil {
			return SignersDataMsg{Err: err}
		}
		return SignersDataMsg{Signers: resp.Signers, Total: resp.Total, HasMore: resp.HasMore, Err: nil}
	}
}

func (m *SignersModel) createSigner(signerType string, password string) tea.Cmd {
	return func() tea.Msg {
		req := &evm.CreateSignerRequest{
			Type: signerType,
		}
		if signerType == "keystore" {
			req.Keystore = &evm.CreateKeystoreParams{
				Password: password,
			}
		}

		signer, err := m.signers_svc.Create(m.ctx, req)
		if err != nil {
			return SignerCreateMsg{Success: false, Err: err}
		}
		return SignerCreateMsg{
			Signer:  signer,
			Success: true,
			Message: fmt.Sprintf("Signer created: %s", signer.Address),
			Err:     nil,
		}
	}
}

func (m *SignersModel) unlockSigner(address string, password string) tea.Cmd {
	return func() tea.Msg {
		req := &evm.UnlockSignerRequest{Password: password}
		resp, err := m.signers_svc.Unlock(m.ctx, address, req)
		if err != nil {
			return SignerUnlockMsg{Address: address, Success: false, Err: err}
		}
		return SignerUnlockMsg{
			Address: address,
			Signer:  resp,
			Success: true,
			Message: fmt.Sprintf("Signer unlocked: %s", resp.Address),
		}
	}
}

func (m *SignersModel) lockSigner(address string) tea.Cmd {
	return func() tea.Msg {
		resp, err := m.signers_svc.Lock(m.ctx, address)
		if err != nil {
			return SignerLockMsg{Success: false, Err: err}
		}
		return SignerLockMsg{
			Signer:  resp,
			Success: true,
			Message: fmt.Sprintf("Signer locked: %s", resp.Address),
		}
	}
}

func (m *SignersModel) loadHDWallets() tea.Cmd {
	return func() tea.Msg {
		if m.hdwallets_svc == nil {
			return SignerHDWalletListMsg{Err: fmt.Errorf("HD wallet service not available")}
		}
		resp, err := m.hdwallets_svc.List(m.ctx)
		if err != nil {
			return SignerHDWalletListMsg{Err: err}
		}
		return SignerHDWalletListMsg{Wallets: resp.Wallets}
	}
}

func (m *SignersModel) deriveFromHDWallet(primaryAddr string, index uint32) tea.Cmd {
	return func() tea.Msg {
		req := &evm.DeriveAddressRequest{Index: &index}
		resp, err := m.hdwallets_svc.DeriveAddress(m.ctx, primaryAddr, req)
		if err != nil {
			return SignerHDDeriveMsg{Success: false, Err: err}
		}
		msg := "Derived address"
		if len(resp.Derived) > 0 {
			msg = fmt.Sprintf("Derived signer: %s", resp.Derived[0].Address)
		}
		return SignerHDDeriveMsg{
			Derived: resp.Derived,
			Success: true,
			Message: msg,
		}
	}
}

// Update handles messages
func (m *SignersModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case SignersDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.signers = msg.Signers
			m.total = msg.Total
			m.hasMore = msg.HasMore
			m.err = nil
		}
		return m, nil

	case SignerCreateMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.resetCreateState()
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			return m, m.Refresh()
		}
		return m, nil

	case SignerHDWalletListMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
			m.createStep = 0 // Go back to type selection
		} else {
			m.hdWallets = msg.Wallets
			if len(msg.Wallets) == 0 {
				m.actionResult = styles.ErrorStyle.Render("No HD wallets found. Create one first in the HD Wallets tab.")
				m.createStep = 0
			} else {
				m.createStep = 2 // Show wallet picker
				m.hdWalletIdx = 0
			}
		}
		return m, nil

	case SignerUnlockMsg:
		m.loading = false
		if msg.Err != nil {
			// Security: track failed attempts for rate limiting
			m.unlockAttempts[msg.Address]++
			if m.unlockAttempts[msg.Address] >= maxUnlockAttempts {
				m.unlockCooldownUtil[msg.Address] = time.Now().Add(unlockCooldownDuration)
				m.unlockAttempts[msg.Address] = 0
				m.showUnlock = false
				m.actionResult = styles.ErrorStyle.Render(
					fmt.Sprintf("Too many failed attempts for %s. Locked for %s",
						msg.Address, unlockCooldownDuration),
				)
			} else {
				remaining := maxUnlockAttempts - m.unlockAttempts[msg.Address]
				m.actionResult = styles.ErrorStyle.Render(
					fmt.Sprintf("Error: %v (%d attempts remaining)", msg.Err, remaining),
				)
			}
		} else {
			// Success: clear rate limit state
			delete(m.unlockAttempts, msg.Address)
			delete(m.unlockCooldownUtil, msg.Address)
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.showUnlock = false
			return m, m.Refresh()
		}
		return m, nil

	case SignerLockMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			return m, m.Refresh()
		}
		return m, nil

	case SignerHDDeriveMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.resetCreateState()
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
		// Handle unlock password input
		if m.showUnlock {
			switch msg.String() {
			case "enter":
				password := m.unlockInput.Value()
				// Security: clear password from input immediately after extraction
				m.unlockInput.SetValue("")
				m.unlockInput.Blur()
				if password != "" {
					signer := m.GetSelectedSigner()
					if signer != nil {
						// Security: check rate limit before attempting unlock
						if cooldown, ok := m.unlockCooldownUtil[signer.Address]; ok && time.Now().Before(cooldown) {
							remaining := time.Until(cooldown).Truncate(time.Second)
							m.actionResult = styles.ErrorStyle.Render(
								fmt.Sprintf("Too many failed attempts. Try again in %s", remaining),
							)
							return m, nil
						}
						m.loading = true
						return m, tea.Batch(m.spinner.Tick, m.unlockSigner(signer.Address, password))
					}
				}
				return m, nil
			case "esc":
				m.showUnlock = false
				// Security: clear password on cancel
				m.unlockInput.SetValue("")
				m.unlockInput.Blur()
				return m, nil
			default:
				var cmd tea.Cmd
				m.unlockInput, cmd = m.unlockInput.Update(msg)
				return m, cmd
			}
		}

		// Handle create signer flow
		if m.showCreate {
			return m.handleCreateInput(msg)
		}

		// Handle filter input
		if m.showFilter {
			switch msg.String() {
			case "enter":
				m.typeFilter = m.filterInput.Value()
				m.showFilter = false
				m.filterInput.Blur()
				m.offset = 0
				m.selectedIdx = 0
				return m, m.Refresh()
			case "esc":
				m.showFilter = false
				m.filterInput.Blur()
				return m, nil
			default:
				var cmd tea.Cmd
				m.filterInput, cmd = m.filterInput.Update(msg)
				return m, cmd
			}
		}

		// Normal key handling
		switch msg.String() {
		case "r":
			return m, m.Refresh()
		case "f":
			m.showFilter = true
			m.filterInput.Placeholder = "Signer type (private_key, keystore)"
			m.filterInput.Focus()
			return m, textinput.Blink
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.selectedIdx < len(m.signers)-1 {
				m.selectedIdx++
			}
			return m, nil
		case "pgup", "ctrl+u":
			m.selectedIdx -= 10
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			return m, nil
		case "pgdown", "ctrl+d":
			m.selectedIdx += 10
			if m.selectedIdx >= len(m.signers) {
				m.selectedIdx = len(m.signers) - 1
			}
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			return m, nil
		case "home", "g":
			m.selectedIdx = 0
			return m, nil
		case "end", "G":
			if len(m.signers) > 0 {
				m.selectedIdx = len(m.signers) - 1
			}
			return m, nil
		case "n":
			// Next page
			if m.offset+m.limit < m.total {
				m.offset += m.limit
				m.selectedIdx = 0
				return m, m.Refresh()
			}
			return m, nil
		case "p":
			// Previous page
			if m.offset > 0 {
				m.offset -= m.limit
				if m.offset < 0 {
					m.offset = 0
				}
				m.selectedIdx = 0
				return m, m.Refresh()
			}
			return m, nil
		case "c":
			// Clear filters
			m.typeFilter = ""
			m.filterInput.SetValue("")
			m.offset = 0
			m.selectedIdx = 0
			return m, m.Refresh()
		case "u":
			// Unlock selected signer
			signer := m.GetSelectedSigner()
			if signer != nil && signer.Locked {
				// Security: check cooldown before showing form
				if cooldown, ok := m.unlockCooldownUtil[signer.Address]; ok && time.Now().Before(cooldown) {
					remaining := time.Until(cooldown).Truncate(time.Second)
					m.actionResult = styles.ErrorStyle.Render(
						fmt.Sprintf("Too many failed attempts. Try again in %s", remaining),
					)
					return m, nil
				}
				m.showUnlock = true
				m.unlockInput.SetValue("")
				m.unlockInput.Focus()
				m.actionResult = ""
				return m, textinput.Blink
			}
			return m, nil
		case "l":
			// Lock selected signer
			signer := m.GetSelectedSigner()
			if signer != nil && !signer.Locked && signer.Enabled {
				m.loading = true
				m.actionResult = ""
				return m, tea.Batch(m.spinner.Tick, m.lockSigner(signer.Address))
			}
			return m, nil
		case "+", "a":
			// Create new signer
			m.showCreate = true
			m.createStep = 0
			m.selectedType = ""
			m.actionResult = ""
			return m, nil
		}
	}

	return m, nil
}

func (m *SignersModel) resetCreateState() {
	m.showCreate = false
	m.createStep = 0
	m.typeIdx = 0
	m.selectedType = ""
	m.actionResult = ""
	m.showPassword = false
	m.passwordInput.SetValue("")
	m.passwordInput.Blur()
	m.passwordInput.EchoMode = textinput.EchoPassword
	m.confirmInput.SetValue("")
	m.confirmInput.Blur()
	m.confirmInput.EchoMode = textinput.EchoPassword
	m.indexInput.SetValue("")
	m.indexInput.Blur()
	m.hdWallets = nil
	m.hdWalletIdx = 0
}

func (m *SignersModel) handleCreateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.createStep {
	case 0: // Select type
		switch msg.String() {
		case "up", "k":
			if m.typeIdx > 0 {
				m.typeIdx--
			}
			return m, nil
		case "down", "j":
			if m.typeIdx < 1 {
				m.typeIdx++
			}
			return m, nil
		case "enter":
			if m.typeIdx == 0 {
				m.selectedType = "keystore"
				m.createStep = 1
				m.passwordInput.Focus()
				return m, textinput.Blink
			}
			m.selectedType = "hd_wallet"
			m.createStep = 1
			m.loading = true
			m.actionResult = ""
			return m, tea.Batch(m.spinner.Tick, m.loadHDWallets())
		case "esc":
			m.resetCreateState()
			return m, nil
		}
	case 1: // Enter password (keystore) — HD wallet loading is handled by message
		if m.selectedType == "keystore" {
			switch msg.String() {
			case "enter":
				if m.passwordInput.Value() != "" {
					// Security: enforce password complexity
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
				m.resetCreateState()
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
	case 2:
		if m.selectedType == "keystore" {
			// Confirm password
			switch msg.String() {
			case "enter":
				password := m.passwordInput.Value()
				confirm := m.confirmInput.Value()
				if confirm == password {
					// Security: clear passwords from inputs immediately
					m.passwordInput.SetValue("")
					m.confirmInput.SetValue("")
					m.confirmInput.Blur()
					m.loading = true
					return m, tea.Batch(m.spinner.Tick, m.createSigner(m.selectedType, password))
				}
				m.actionResult = styles.ErrorStyle.Render("Passwords do not match")
				return m, nil
			case "esc":
				m.resetCreateState()
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
		// HD wallet picker
		return m.handleHDWalletPicker(msg)
	case 3: // HD wallet derive index
		return m.handleHDDeriveIndex(msg)
	}
	return m, nil
}

func (m *SignersModel) handleHDWalletPicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.hdWalletIdx > 0 {
			m.hdWalletIdx--
		}
		return m, nil
	case "down", "j":
		if m.hdWalletIdx < len(m.hdWallets)-1 {
			m.hdWalletIdx++
		}
		return m, nil
	case "enter":
		if len(m.hdWallets) > 0 {
			m.createStep = 3
			m.indexInput.Focus()
			return m, textinput.Blink
		}
		return m, nil
	case "esc":
		m.resetCreateState()
		return m, nil
	}
	return m, nil
}

func (m *SignersModel) handleHDDeriveIndex(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		idx, err := strconv.ParseUint(m.indexInput.Value(), 10, 32)
		if err != nil {
			m.actionResult = styles.ErrorStyle.Render("Invalid index: must be a number")
			return m, nil
		}
		wallet := m.hdWallets[m.hdWalletIdx]
		m.loading = true
		m.indexInput.Blur()
		return m, tea.Batch(m.spinner.Tick, m.deriveFromHDWallet(wallet.PrimaryAddress, uint32(idx)))
	case "esc":
		m.resetCreateState()
		return m, nil
	default:
		var cmd tea.Cmd
		m.indexInput, cmd = m.indexInput.Update(msg)
		return m, cmd
	}
}

// View renders the signers view
func (m *SignersModel) View() string {
	if m.showUnlock {
		return m.renderUnlockForm()
	}

	if m.showCreate {
		return m.renderCreateForm()
	}

	if m.showFilter {
		return m.renderFilterInput()
	}

	if m.loading {
		return m.renderLoading()
	}

	if m.err != nil {
		return m.renderError()
	}

	return m.renderSigners()
}

func (m *SignersModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading signers...", m.spinner.View()),
	)
}

func (m *SignersModel) renderError() string {
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

func (m *SignersModel) renderUnlockForm() string {
	var content strings.Builder
	signer := m.GetSelectedSigner()
	addr := ""
	if signer != nil {
		addr = signer.Address
	}

	content.WriteString(styles.TitleStyle.Render("Unlock Signer"))
	content.WriteString("\n\n")
	content.WriteString(fmt.Sprintf("Address: %s\n\n", styles.HighlightStyle.Render(addr)))
	content.WriteString(styles.SubtitleStyle.Render("Enter Password:"))
	content.WriteString("\n\n")
	content.WriteString(m.unlockInput.View())
	content.WriteString("\n\n")
	if m.actionResult != "" {
		content.WriteString(m.actionResult)
		content.WriteString("\n\n")
	}
	content.WriteString(styles.MutedColor.Render("Enter: unlock | Esc: cancel"))

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}

func (m *SignersModel) renderFilterInput() string {
	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Filter by Type"))
	content.WriteString("\n\n")
	content.WriteString(m.filterInput.View())
	content.WriteString("\n\n")
	content.WriteString(styles.MutedColor.Render("Press Enter to apply, Esc to cancel"))

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}

func (m *SignersModel) renderCreateForm() string {
	var content strings.Builder

	content.WriteString(styles.TitleStyle.Render("Create New Signer"))
	content.WriteString("\n\n")

	switch m.createStep {
	case 0:
		content.WriteString(styles.SubtitleStyle.Render("Select Signer Type:"))
		content.WriteString("\n\n")
		typeOptions := []string{"Keystore", "Derive from HD Wallet"}
		for i, opt := range typeOptions {
			if i == m.typeIdx {
				content.WriteString(styles.TableSelectedRowStyle.Render("> " + opt))
			} else {
				content.WriteString(styles.TableRowStyle.Render("  " + opt))
			}
			content.WriteString("\n")
		}
		content.WriteString("\n")
		if m.actionResult != "" {
			content.WriteString(m.actionResult)
			content.WriteString("\n\n")
		}
		content.WriteString(styles.MutedColor.Render("up/down: select | Enter: confirm | Esc: cancel"))

	case 1:
		if m.selectedType == "keystore" {
			fmt.Fprintf(&content, "Type: %s\n\n", styles.HighlightStyle.Render(m.selectedType))
			content.WriteString(styles.SubtitleStyle.Render("Enter Password:"))
			content.WriteString("\n")
			content.WriteString(styles.MutedColor.Render(
				fmt.Sprintf("(min %d chars: upper+lower+digit+symbol, %d+ recommended)",
					minPasswordLength, recommendedPasswordLength),
			))
			content.WriteString("\n\n")
			content.WriteString(m.passwordInput.View())
			content.WriteString("\n\n")
			if m.actionResult != "" {
				content.WriteString(m.actionResult)
				content.WriteString("\n\n")
			}
			if m.showPassword {
				content.WriteString(styles.MutedColor.Render("Tab: hide password | Enter: continue | Esc: cancel"))
			} else {
				content.WriteString(styles.MutedColor.Render("Tab: show password | Enter: continue | Esc: cancel"))
			}
		}
		// HD wallet: step 1 is loading state, handled by spinner

	case 2:
		if m.selectedType == "keystore" {
			fmt.Fprintf(&content, "Type: %s\n\n", styles.HighlightStyle.Render(m.selectedType))
			content.WriteString(styles.SubtitleStyle.Render("Confirm Password:"))
			content.WriteString("\n\n")
			content.WriteString(m.confirmInput.View())
			content.WriteString("\n\n")
			// Show recommendation warning if password is valid but short
			if _, warnMsg := validatePassword(m.passwordInput.Value()); warnMsg != "" {
				content.WriteString(styles.WarningStyle.Render(warnMsg))
				content.WriteString("\n\n")
			}
			if m.actionResult != "" {
				content.WriteString(m.actionResult)
				content.WriteString("\n\n")
			}
			if m.showPassword {
				content.WriteString(styles.MutedColor.Render("Tab: hide password | Enter: create | Esc: cancel"))
			} else {
				content.WriteString(styles.MutedColor.Render("Tab: show password | Enter: create | Esc: cancel"))
			}
		} else {
			// HD wallet picker
			m.renderHDWalletPicker(&content)
		}

	case 3:
		// HD wallet derive index
		m.renderHDDeriveIndex(&content)
	}

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}

func (m *SignersModel) renderHDWalletPicker(content *strings.Builder) {
	content.WriteString(styles.SubtitleStyle.Render("Select Source Wallet:"))
	content.WriteString("\n\n")

	for i, w := range m.hdWallets {
		addr := w.PrimaryAddress
		if len(addr) > 20 {
			addr = addr[:10] + "..." + addr[len(addr)-6:]
		}
		label := fmt.Sprintf("%s  (%s, %d derived)", addr, w.BasePath, w.DerivedCount)
		if i == m.hdWalletIdx {
			content.WriteString(styles.TableSelectedRowStyle.Render("> " + label))
		} else {
			content.WriteString(styles.TableRowStyle.Render("  " + label))
		}
		content.WriteString("\n")
	}

	content.WriteString("\n")
	content.WriteString(styles.MutedColor.Render("up/down: navigate | Enter: select | Esc: back"))
}

func (m *SignersModel) renderHDDeriveIndex(content *strings.Builder) {
	wallet := m.hdWallets[m.hdWalletIdx]
	addr := wallet.PrimaryAddress
	if len(addr) > 20 {
		addr = addr[:10] + "..." + addr[len(addr)-6:]
	}

	fmt.Fprintf(content, "Wallet: %s\n", styles.HighlightStyle.Render(addr))
	fmt.Fprintf(content, "Current derived count: %d\n\n", wallet.DerivedCount)
	content.WriteString(styles.SubtitleStyle.Render("Enter derivation index:"))
	content.WriteString("\n\n")
	content.WriteString(m.indexInput.View())
	content.WriteString("\n\n")
	if m.actionResult != "" {
		content.WriteString(m.actionResult)
		content.WriteString("\n\n")
	}
	content.WriteString(styles.MutedColor.Render("Enter: derive | Esc: cancel"))
}

// hasAccessColumn returns true if any signer has AllowedKeys (admin view).
func (m *SignersModel) hasAccessColumn() bool {
	for _, s := range m.signers {
		if len(s.AllowedKeys) > 0 {
			return true
		}
	}
	return false
}

// formatAccessColumn formats the AllowedKeys list into a short display string.
func formatAccessColumn(keys []evm.AllowedKeyInfo) string {
	if len(keys) == 0 {
		return "-"
	}
	const maxShow = 2
	names := make([]string, 0, maxShow)
	for i, k := range keys {
		if i >= maxShow {
			break
		}
		names = append(names, k.Name)
	}
	result := strings.Join(names, ", ")
	if len(keys) > maxShow {
		result += fmt.Sprintf(" (+%d)", len(keys)-maxShow)
	}
	return result
}

func (m *SignersModel) renderSigners() string {
	var content strings.Builder

	// Header
	header := styles.SubtitleStyle.Render("Signers")
	if m.typeFilter != "" {
		header += styles.MutedColor.Render(fmt.Sprintf(" (filtered: type=%s)", m.typeFilter))
	}
	content.WriteString(header)
	content.WriteString("\n\n")

	// Action result
	if m.actionResult != "" {
		content.WriteString(m.actionResult)
		content.WriteString("\n\n")
	}

	// Table header
	showAccess := m.hasAccessColumn()
	if showAccess {
		headerRow := fmt.Sprintf("%-44s  %-14s  %-8s  %-8s  %-30s",
			"Address", "Type", "Status", "Enabled", "Access")
		content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	} else {
		headerRow := fmt.Sprintf("%-44s  %-14s  %-8s  %-8s",
			"Address", "Type", "Status", "Enabled")
		content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	}
	content.WriteString("\n")

	// Rows
	if len(m.signers) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No signers found"))
	} else {
		for i, signer := range m.signers {
			row := m.renderSignerRow(signer, i == m.selectedIdx, showAccess)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	// Pagination info
	content.WriteString("\n")
	startIdx := m.offset + 1
	endIdx := m.offset + len(m.signers)
	if endIdx > m.total {
		endIdx = m.total
	}
	if len(m.signers) == 0 {
		startIdx = 0
		endIdx = 0
	}
	pagination := fmt.Sprintf("Showing %d-%d of %d", startIdx, endIdx, m.total)
	if m.hasMore {
		pagination += " (more available)"
	}
	content.WriteString(styles.MutedColor.Render(pagination))

	// Help
	content.WriteString("\n\n")
	helpText := "Enter: view detail | up/down: navigate | u: unlock | l: lock | +/a: create signer | f: filter | c: clear | n/p: next/prev | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

// GetSelectedSigner returns the currently selected signer, or nil if none selected.
func (m *SignersModel) GetSelectedSigner() *evm.Signer {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.signers) {
		return nil
	}
	return &m.signers[m.selectedIdx]
}

// IsCapturingInput returns true when this view is capturing keyboard input (form/filter active).
func (m *SignersModel) IsCapturingInput() bool {
	return m.showCreate || m.showFilter || m.showUnlock
}

func (m *SignersModel) renderSignerRow(signer evm.Signer, selected bool, showAccess bool) string {
	// Format address
	address := signer.Address
	if len(address) > 44 {
		address = address[:41] + "..."
	}

	enabled := "Yes"
	if !signer.Enabled {
		enabled = "No"
	}

	status := "Ready"
	if signer.Locked {
		status = "Locked"
	}

	accessStr := ""
	if showAccess {
		accessStr = formatAccessColumn(signer.AllowedKeys)
	}

	if showAccess {
		row := fmt.Sprintf("%-44s  %-14s  %-8s  %-8s  %-30s",
			address,
			signer.Type,
			status,
			enabled,
			accessStr,
		)
		if selected {
			return styles.TableSelectedRowStyle.Render(row)
		}
	} else {
		row := fmt.Sprintf("%-44s  %-14s  %-8s  %-8s",
			address,
			signer.Type,
			status,
			enabled,
		)
		if selected {
			return styles.TableSelectedRowStyle.Render(row)
		}
	}

	// Color type
	typeStyle := styles.MutedColor
	switch signer.Type {
	case "private_key":
		typeStyle = styles.WarningStyle
	case "keystore":
		typeStyle = styles.SuccessStyle
	}
	typePart := typeStyle.Render(fmt.Sprintf("%-14s", signer.Type))

	// Color status
	statusStyle := styles.SuccessStyle
	if signer.Locked {
		statusStyle = styles.WarningStyle
	}
	statusPart := statusStyle.Render(fmt.Sprintf("%-8s", status))

	// Color enabled
	enabledStyle := styles.SuccessStyle
	if !signer.Enabled {
		enabledStyle = styles.MutedColor
	}
	enabledPart := enabledStyle.Render(fmt.Sprintf("%-8s", enabled))

	if showAccess {
		row := fmt.Sprintf("%-44s  %s  %s  %s  %-30s",
			address,
			typePart,
			statusPart,
			enabledPart,
			accessStr,
		)
		return styles.TableRowStyle.Render(row)
	}

	row := fmt.Sprintf("%-44s  %s  %s  %s",
		address,
		typePart,
		statusPart,
		enabledPart,
	)
	return styles.TableRowStyle.Render(row)
}
