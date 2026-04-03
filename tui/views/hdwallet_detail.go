package views

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// HDWalletDetailModel represents the HD wallet detail view.
type HDWalletDetailModel struct {
	hdwallets_svc evm.HDWalletAPI
	signers_svc   evm.SignerAPI // for unlock
	ctx           context.Context
	width         int
	height        int
	spinner       spinner.Model
	loading       bool
	err           error
	primaryAddr   string
	seedWallet    evm.HDWalletResponse // snapshot from list (name/tags/base path) when opening detail
	wallet        *evm.HDWalletResponse
	primarySigner *evm.Signer // display_name / tags for primary (from signer_ownership)
	derived       []evm.SignerInfo
	locked        bool // true when wallet is locked (ListDerived failed)
	selectedIdx   int
	goBack        bool
	actionResult  string

	// Edit labels (primary address)
	showEditLabels bool
	editFocus      int
	editNameInput  textinput.Model
	editTagsInput  textinput.Model

	// Derive form state
	showDerive  bool
	deriveMode  string // "single" or "batch"
	indexInput  textinput.Model
	startInput  textinput.Model
	countInput  textinput.Model
	activeField string // "start" or "count" for batch mode

	// Unlock form state (when wallet is locked)
	showUnlock  bool
	unlockInput textinput.Model
}

// HDWalletDetailDataMsg is sent when HD wallet detail data is loaded.
type HDWalletDetailDataMsg struct {
	Wallet        *evm.HDWalletResponse
	PrimarySigner *evm.Signer
	Derived       []evm.SignerInfo
	Err           error
	Locked        bool // true when wallet is locked (ListDerived failed)
}

// HDWalletDeriveMsg is sent when addresses are derived.
type HDWalletDeriveMsg struct {
	Derived []evm.SignerInfo
	Success bool
	Message string
	Err     error
}

// HDWalletDetailUnlockMsg is sent when an HD wallet unlock completes in detail view.
type HDWalletDetailUnlockMsg struct {
	Success bool
	Message string
	Err     error
}

// NewHDWalletDetailModel creates a new HD wallet detail model.
func NewHDWalletDetailModel(c *client.Client, ctx context.Context) (*HDWalletDetailModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newHDWalletDetailModelFromService(c.EVM.HDWallets, c.EVM.Signers, ctx)
}

// newHDWalletDetailModelFromService creates an HD wallet detail model from services (for testing, signers_svc may be nil).
func newHDWalletDetailModelFromService(hdSvc evm.HDWalletAPI, signersSvc evm.SignerAPI, ctx context.Context) (*HDWalletDetailModel, error) {
	if hdSvc == nil {
		return nil, fmt.Errorf("HD wallet service is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	indexInput := textinput.New()
	indexInput.Placeholder = "Derivation index"
	indexInput.Width = 20

	startInput := textinput.New()
	startInput.Placeholder = "Start index"
	startInput.Width = 20

	countInput := textinput.New()
	countInput.Placeholder = "Count (1-100)"
	countInput.Width = 20

	unlockInput := textinput.New()
	unlockInput.Placeholder = "Enter password to unlock"
	unlockInput.Width = 40
	unlockInput.EchoMode = textinput.EchoPassword

	editName := textinput.New()
	editName.Placeholder = "Display name (optional)"
	editName.Width = 50

	editTags := textinput.New()
	editTags.Placeholder = "Tags: comma-separated"
	editTags.Width = 50

	return &HDWalletDetailModel{
		hdwallets_svc: hdSvc,
		signers_svc:   signersSvc,
		ctx:           ctx,
		spinner:       s,
		indexInput:    indexInput,
		startInput:    startInput,
		countInput:    countInput,
		unlockInput:   unlockInput,
		editNameInput: editName,
		editTagsInput: editTags,
	}, nil
}

// Init initializes the view.
func (m *HDWalletDetailModel) Init() tea.Cmd {
	return nil
}

// SetSize sets the view size.
func (m *HDWalletDetailModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// LoadWallet loads an HD wallet's derived addresses. Pass the row from the list so name/tags stay in sync.
func (m *HDWalletDetailModel) LoadWallet(w evm.HDWalletResponse) tea.Cmd {
	if w.PrimaryAddress == "" {
		return nil
	}
	m.loading = true
	m.seedWallet = w
	m.primaryAddr = w.PrimaryAddress
	m.wallet = nil
	m.derived = nil
	m.locked = false
	m.goBack = false
	m.actionResult = ""
	m.showDerive = false
	m.showUnlock = false
	m.showEditLabels = false
	m.primarySigner = nil

	return tea.Batch(
		m.spinner.Tick,
		m.loadWalletData(),
	)
}

// ShouldGoBack returns true if the view should go back to the list.
func (m *HDWalletDetailModel) ShouldGoBack() bool {
	return m.goBack
}

// ResetGoBack resets the go back flag.
func (m *HDWalletDetailModel) ResetGoBack() {
	m.goBack = false
}

func (m *HDWalletDetailModel) loadWalletData() tea.Cmd {
	return func() tea.Msg {
		primaryAddr := m.primaryAddr
		ps := m.fetchPrimarySignerLabels(primaryAddr)
		if m.seedWallet.DisplayName != "" || len(m.seedWallet.Tags) > 0 {
			if ps == nil {
				ps = &evm.Signer{Address: primaryAddr, Type: "hd_wallet"}
			}
			if m.seedWallet.DisplayName != "" {
				ps.DisplayName = m.seedWallet.DisplayName
			}
			if len(m.seedWallet.Tags) > 0 {
				ps.Tags = m.seedWallet.Tags
			}
		}
		resp, err := m.hdwallets_svc.ListDerived(m.ctx, primaryAddr)
		if err != nil {
			w := evm.HDWalletResponse{PrimaryAddress: primaryAddr, Locked: true}
			if m.seedWallet.BasePath != "" {
				w.BasePath = m.seedWallet.BasePath
			}
			w.DisplayName = m.seedWallet.DisplayName
			w.Tags = m.seedWallet.Tags
			return HDWalletDetailDataMsg{
				Wallet:        &w,
				PrimarySigner: ps,
				Derived:       nil,
				Err:           err,
				Locked:        true,
			}
		}

		wallet := &evm.HDWalletResponse{
			PrimaryAddress: primaryAddr,
			BasePath:       m.seedWallet.BasePath,
			DerivedCount:   len(resp.Derived),
			Locked:         false,
			DisplayName:    m.seedWallet.DisplayName,
			Tags:           m.seedWallet.Tags,
		}
		if ps != nil {
			if wallet.DisplayName == "" {
				wallet.DisplayName = ps.DisplayName
			}
			if len(wallet.Tags) == 0 {
				wallet.Tags = ps.Tags
			}
		}

		return HDWalletDetailDataMsg{
			Wallet:        wallet,
			PrimarySigner: ps,
			Derived:       resp.Derived,
		}
	}
}

func (m *HDWalletDetailModel) fetchPrimarySignerLabels(primaryAddr string) *evm.Signer {
	if m.signers_svc == nil {
		return nil
	}
	listResp, err := m.signers_svc.List(m.ctx, &evm.ListSignersFilter{Type: "hd_wallet", Limit: 500})
	if err != nil || listResp == nil {
		return nil
	}
	for i := range listResp.Signers {
		if strings.EqualFold(listResp.Signers[i].Address, primaryAddr) {
			return &listResp.Signers[i]
		}
	}
	return nil
}

func (m *HDWalletDetailModel) patchPrimaryLabels(displayName, tagsCSV string) tea.Cmd {
	return func() tea.Msg {
		if m.signers_svc == nil {
			return SignerLabelsPatchMsg{Success: false, Err: fmt.Errorf("signer service not available")}
		}
		tags := ParseTagsCSV(tagsCSV)
		dn := strings.TrimSpace(displayName)
		dnPtr := &dn
		tagsPtr := &tags
		req := &evm.PatchSignerLabelsRequest{DisplayName: dnPtr, Tags: tagsPtr}
		signer, err := m.signers_svc.PatchSignerLabels(m.ctx, m.primaryAddr, req)
		if err != nil {
			return SignerLabelsPatchMsg{Success: false, Err: err}
		}
		return SignerLabelsPatchMsg{
			Signer:  signer,
			Success: true,
			Message: fmt.Sprintf("Updated labels for %s", m.primaryAddr),
		}
	}
}

func (m *HDWalletDetailModel) deriveSingle(index uint32) tea.Cmd {
	return func() tea.Msg {
		req := &evm.DeriveAddressRequest{Index: &index}
		resp, err := m.hdwallets_svc.DeriveAddress(m.ctx, m.primaryAddr, req)
		if err != nil {
			return HDWalletDeriveMsg{Success: false, Err: err}
		}
		return HDWalletDeriveMsg{
			Derived: resp.Derived,
			Success: true,
			Message: fmt.Sprintf("Derived %d address(es)", len(resp.Derived)),
		}
	}
}

func (m *HDWalletDetailModel) deriveBatch(start, count uint32) tea.Cmd {
	return func() tea.Msg {
		req := &evm.DeriveAddressRequest{Start: &start, Count: &count}
		resp, err := m.hdwallets_svc.DeriveAddress(m.ctx, m.primaryAddr, req)
		if err != nil {
			return HDWalletDeriveMsg{Success: false, Err: err}
		}
		return HDWalletDeriveMsg{
			Derived: resp.Derived,
			Success: true,
			Message: fmt.Sprintf("Derived %d address(es)", len(resp.Derived)),
		}
	}
}

func (m *HDWalletDetailModel) unlockWallet(password string) tea.Cmd {
	return func() tea.Msg {
		if m.signers_svc == nil {
			return HDWalletDetailUnlockMsg{Success: false, Err: fmt.Errorf("unlock not available")}
		}
		req := &evm.UnlockSignerRequest{Password: password}
		resp, err := m.signers_svc.Unlock(m.ctx, m.primaryAddr, req)
		if err != nil {
			return HDWalletDetailUnlockMsg{Success: false, Err: err}
		}
		return HDWalletDetailUnlockMsg{
			Success: true,
			Message: fmt.Sprintf("HD wallet unlocked: %s", resp.Address),
		}
	}
}

// Update handles messages.
func (m *HDWalletDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case HDWalletDetailDataMsg:
		m.loading = false
		m.wallet = msg.Wallet
		m.primarySigner = msg.PrimarySigner
		m.derived = msg.Derived
		m.locked = msg.Locked
		if m.wallet != nil {
			m.seedWallet = *m.wallet
		}
		if msg.Err != nil && !msg.Locked {
			m.err = msg.Err
		} else {
			m.err = nil
		}
		return m, nil

	case SignerLabelsPatchMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.showEditLabels = false
			m.editNameInput.Blur()
			m.editTagsInput.Blur()
			if msg.Signer != nil {
				m.primarySigner = msg.Signer
				m.seedWallet.DisplayName = msg.Signer.DisplayName
				m.seedWallet.Tags = msg.Signer.Tags
			}
			return m, m.LoadWallet(m.seedWallet)
		}
		return m, nil

	case HDWalletDeriveMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.resetDeriveForm()
			return m, m.LoadWallet(m.seedWallet)
		}
		return m, nil

	case HDWalletDetailUnlockMsg:
		m.loading = false
		m.showUnlock = false
		m.unlockInput.SetValue("")
		m.unlockInput.Blur()
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Unlock failed: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			return m, m.LoadWallet(m.seedWallet)
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
		if m.showEditLabels {
			switch msg.String() {
			case "esc":
				m.showEditLabels = false
				m.editNameInput.Blur()
				m.editTagsInput.Blur()
				return m, nil
			case "tab":
				if m.editFocus == 0 {
					m.editFocus = 1
					m.editNameInput.Blur()
					m.editTagsInput.Focus()
				} else {
					m.editFocus = 0
					m.editTagsInput.Blur()
					m.editNameInput.Focus()
				}
				return m, textinput.Blink
			case "enter":
				if m.primaryAddr == "" {
					m.showEditLabels = false
					return m, nil
				}
				m.loading = true
				m.actionResult = ""
				return m, tea.Batch(m.spinner.Tick, m.patchPrimaryLabels(
					m.editNameInput.Value(),
					m.editTagsInput.Value(),
				))
			default:
				var cmd tea.Cmd
				if m.editFocus == 0 {
					m.editNameInput, cmd = m.editNameInput.Update(msg)
				} else {
					m.editTagsInput, cmd = m.editTagsInput.Update(msg)
				}
				return m, cmd
			}
		}
		if m.showDerive {
			return m.handleDeriveInput(msg)
		}

		switch msg.String() {
		case "esc", "backspace":
			m.goBack = true
			return m, nil
		case "u":
			// Unlock when wallet is locked
			if m.locked && m.signers_svc != nil {
				m.showUnlock = true
				m.unlockInput.SetValue("")
				m.unlockInput.Focus()
				return m, textinput.Blink
			}
			return m, nil
		case "d":
			if !m.locked {
				m.showDerive = true
				m.deriveMode = "single"
				m.actionResult = ""
				m.indexInput.Focus()
				return m, textinput.Blink
			}
			return m, nil
		case "b":
			if !m.locked {
				m.showDerive = true
				m.deriveMode = "batch"
				m.activeField = "start"
				m.actionResult = ""
				m.startInput.Focus()
				return m, textinput.Blink
			}
			return m, nil
		case "e":
			if m.signers_svc != nil && m.primaryAddr != "" {
				lab := m.primarySigner
				dn := ""
				var tags []string
				if lab != nil {
					dn = lab.DisplayName
					tags = lab.Tags
				}
				m.showEditLabels = true
				m.editFocus = 0
				m.editNameInput.SetValue(dn)
				m.editTagsInput.SetValue(strings.Join(tags, ", "))
				m.editNameInput.Focus()
				m.editTagsInput.Blur()
				return m, textinput.Blink
			}
			return m, nil
		case "r":
			if m.primaryAddr != "" {
				return m, m.LoadWallet(m.seedWallet)
			}
			return m, nil
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.selectedIdx < len(m.derived)-1 {
				m.selectedIdx++
			}
			return m, nil
		}
	}

	return m, nil
}

func (m *HDWalletDetailModel) handleDeriveInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.deriveMode == "single" {
		return m.handleSingleDeriveInput(msg)
	}
	return m.handleBatchDeriveInput(msg)
}

func (m *HDWalletDetailModel) handleSingleDeriveInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		idx, err := strconv.ParseUint(m.indexInput.Value(), 10, 32)
		if err != nil {
			m.actionResult = styles.ErrorStyle.Render("Invalid index: must be a number")
			return m, nil
		}
		m.loading = true
		m.indexInput.Blur()
		return m, tea.Batch(m.spinner.Tick, m.deriveSingle(uint32(idx)))
	case "esc":
		m.resetDeriveForm()
		return m, nil
	default:
		var cmd tea.Cmd
		m.indexInput, cmd = m.indexInput.Update(msg)
		return m, cmd
	}
}

func (m *HDWalletDetailModel) handleBatchDeriveInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "tab":
		if m.activeField == "start" {
			m.activeField = "count"
			m.startInput.Blur()
			m.countInput.Focus()
			return m, textinput.Blink
		}
		m.activeField = "start"
		m.countInput.Blur()
		m.startInput.Focus()
		return m, textinput.Blink
	case "enter":
		start, err := strconv.ParseUint(m.startInput.Value(), 10, 32)
		if err != nil {
			m.actionResult = styles.ErrorStyle.Render("Invalid start index: must be a number")
			return m, nil
		}
		count, err := strconv.ParseUint(m.countInput.Value(), 10, 32)
		if err != nil || count == 0 || count > 100 {
			m.actionResult = styles.ErrorStyle.Render("Invalid count: must be 1-100")
			return m, nil
		}
		m.loading = true
		m.startInput.Blur()
		m.countInput.Blur()
		return m, tea.Batch(m.spinner.Tick, m.deriveBatch(uint32(start), uint32(count)))
	case "esc":
		m.resetDeriveForm()
		return m, nil
	default:
		var cmd tea.Cmd
		if m.activeField == "start" {
			m.startInput, cmd = m.startInput.Update(msg)
		} else {
			m.countInput, cmd = m.countInput.Update(msg)
		}
		return m, cmd
	}
}

func (m *HDWalletDetailModel) resetDeriveForm() {
	m.showDerive = false
	m.deriveMode = ""
	m.activeField = ""
	m.indexInput.SetValue("")
	m.indexInput.Blur()
	m.startInput.SetValue("")
	m.startInput.Blur()
	m.countInput.SetValue("")
	m.countInput.Blur()
}

func (m *HDWalletDetailModel) handleUnlockInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.unlockInput.Value() != "" {
			password := m.unlockInput.Value()
			m.loading = true
			m.unlockInput.Blur()
			return m, tea.Batch(m.spinner.Tick, m.unlockWallet(password))
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

// View renders the HD wallet detail view.
func (m *HDWalletDetailModel) View() string {
	if m.showUnlock {
		return m.renderUnlockForm()
	}
	if m.showEditLabels {
		return m.renderEditPrimaryLabelsForm()
	}
	if m.showDerive {
		return m.renderDeriveForm()
	}

	if m.loading {
		return m.renderLoading()
	}

	if m.err != nil {
		return m.renderError()
	}

	return m.renderDetail()
}

func (m *HDWalletDetailModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading...", m.spinner.View()),
	)
}

func (m *HDWalletDetailModel) renderError() string {
	errBox := styles.BoxStyle.
		BorderForeground(styles.ErrorColor).
		Render(fmt.Sprintf("Error: %v\n\nPress Esc to go back", m.err))

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		errBox,
	)
}

func (m *HDWalletDetailModel) renderDetail() string {
	if m.wallet == nil {
		return "No wallet loaded"
	}

	var content strings.Builder

	content.WriteString(styles.TitleStyle.Render("HD Wallet Detail"))
	content.WriteString("\n\n")

	if m.actionResult != "" {
		content.WriteString(m.actionResult)
		content.WriteString("\n\n")
	}

	// Wallet info
	fmt.Fprintf(&content, "%s %s\n",
		styles.InfoKeyStyle.Render("Primary Address:"),
		m.primaryAddr)
	dn := ""
	var tags []string
	if m.wallet != nil {
		dn = m.wallet.DisplayName
		tags = m.wallet.Tags
	}
	if m.primarySigner != nil {
		if dn == "" {
			dn = m.primarySigner.DisplayName
		}
		if len(tags) == 0 {
			tags = m.primarySigner.Tags
		}
	}
	if sum := HumanLabelLine(dn, tags); sum != "" {
		content.WriteString(styles.MutedColor.Render(sum))
		content.WriteString("\n")
	}
	if m.locked {
		content.WriteString(styles.WarningStyle.Render("Status: Locked"))
		content.WriteString("\n\n")
		content.WriteString(styles.MutedColor.Render("This wallet is locked. Press 'u' to unlock with password."))
		content.WriteString("\n\n")
		helpText := "u: unlock | e: edit name/tags | Esc: back | r: refresh"
		content.WriteString(styles.HelpStyle.Render(helpText))
		return content.String()
	}
	fmt.Fprintf(&content, "%s %d\n",
		styles.InfoKeyStyle.Render("Total Derived:"),
		len(m.derived))

	content.WriteString("\n")
	content.WriteString(styles.SubtitleStyle.Render("Derived Addresses"))
	content.WriteString("\n")

	// Table header
	headerRow := fmt.Sprintf("%-5s  %-44s  %-12s  %-8s",
		"#", "Address", "Type", "Enabled")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	if len(m.derived) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No derived addresses"))
	} else {
		for i, signer := range m.derived {
			row := m.renderDerivedRow(i, signer, i == m.selectedIdx)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	// Help
	content.WriteString("\n")
	helpText := "d: derive single | b: batch derive | e: edit name/tags | Esc: back | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *HDWalletDetailModel) renderEditPrimaryLabelsForm() string {
	var content strings.Builder
	content.WriteString(styles.TitleStyle.Render("Edit HD Wallet Labels"))
	content.WriteString("\n\n")
	content.WriteString(styles.MutedColor.Render(m.primaryAddr))
	content.WriteString("\n\n")
	content.WriteString(styles.SubtitleStyle.Render("Display name"))
	content.WriteString("\n")
	content.WriteString(m.editNameInput.View())
	content.WriteString("\n\n")
	content.WriteString(styles.SubtitleStyle.Render("Tags (comma-separated)"))
	content.WriteString("\n")
	content.WriteString(m.editTagsInput.View())
	content.WriteString("\n\n")
	content.WriteString(styles.MutedColor.Render("Tab: switch field | Enter: save | Esc: cancel"))
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}

func (m *HDWalletDetailModel) renderUnlockForm() string {
	var content strings.Builder
	content.WriteString(styles.TitleStyle.Render("Unlock HD Wallet"))
	content.WriteString("\n\n")
	content.WriteString(styles.SubtitleStyle.Render("Primary address: " + m.primaryAddr))
	content.WriteString("\n\n")
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

// IsCapturingInput returns true when this view is capturing keyboard input (derive form or unlock form active).
func (m *HDWalletDetailModel) IsCapturingInput() bool {
	return m.showDerive || m.showUnlock || m.showEditLabels
}

func (m *HDWalletDetailModel) renderDerivedRow(index int, signer evm.SignerInfo, selected bool) string {
	address := signer.Address
	if len(address) > 44 {
		address = address[:41] + "..."
	}

	enabled := "Yes"
	if !signer.Enabled {
		enabled = "No"
	}

	row := fmt.Sprintf("%-5d  %-44s  %-12s  %-8s",
		index,
		address,
		signer.Type,
		enabled,
	)

	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}
	return styles.TableRowStyle.Render(row)
}

func (m *HDWalletDetailModel) renderDeriveForm() string {
	var content strings.Builder

	if m.deriveMode == "single" {
		content.WriteString(styles.TitleStyle.Render("Derive Address"))
		content.WriteString("\n\n")
		content.WriteString(styles.SubtitleStyle.Render("Enter derivation index:"))
		content.WriteString("\n\n")
		content.WriteString(m.indexInput.View())
		content.WriteString("\n\n")
		if m.actionResult != "" {
			content.WriteString(m.actionResult)
			content.WriteString("\n\n")
		}
		content.WriteString(styles.MutedColor.Render("Enter: derive | Esc: cancel"))
	} else {
		content.WriteString(styles.TitleStyle.Render("Batch Derive Addresses"))
		content.WriteString("\n\n")
		content.WriteString(styles.SubtitleStyle.Render("Start index:"))
		content.WriteString("\n")
		content.WriteString(m.startInput.View())
		content.WriteString("\n\n")
		content.WriteString(styles.SubtitleStyle.Render("Count (1-100):"))
		content.WriteString("\n")
		content.WriteString(m.countInput.View())
		content.WriteString("\n\n")
		if m.actionResult != "" {
			content.WriteString(m.actionResult)
			content.WriteString("\n\n")
		}
		content.WriteString(styles.MutedColor.Render("Tab: next field | Enter: derive | Esc: cancel"))
	}

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}
