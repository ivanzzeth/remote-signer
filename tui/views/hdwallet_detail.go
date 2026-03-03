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
	ctx           context.Context
	width         int
	height        int
	spinner       spinner.Model
	loading       bool
	err           error
	primaryAddr   string
	wallet        *evm.HDWalletResponse
	derived       []evm.SignerInfo
	selectedIdx   int
	goBack        bool
	actionResult  string

	// Derive form state
	showDerive  bool
	deriveMode  string // "single" or "batch"
	indexInput  textinput.Model
	startInput  textinput.Model
	countInput  textinput.Model
	activeField string // "start" or "count" for batch mode
}

// HDWalletDetailDataMsg is sent when HD wallet detail data is loaded.
type HDWalletDetailDataMsg struct {
	Wallet  *evm.HDWalletResponse
	Derived []evm.SignerInfo
	Err     error
}

// HDWalletDeriveMsg is sent when addresses are derived.
type HDWalletDeriveMsg struct {
	Derived []evm.SignerInfo
	Success bool
	Message string
	Err     error
}

// NewHDWalletDetailModel creates a new HD wallet detail model.
func NewHDWalletDetailModel(c *client.Client, ctx context.Context) (*HDWalletDetailModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newHDWalletDetailModelFromService(c.EVM.HDWallets, ctx)
}

// newHDWalletDetailModelFromService creates an HD wallet detail model from an HDWalletAPI (for testing).
func newHDWalletDetailModelFromService(svc evm.HDWalletAPI, ctx context.Context) (*HDWalletDetailModel, error) {
	if svc == nil {
		return nil, fmt.Errorf("client is required")
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

	return &HDWalletDetailModel{
		hdwallets_svc: svc,
		ctx:           ctx,
		spinner:       s,
		indexInput:    indexInput,
		startInput:    startInput,
		countInput:    countInput,
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

// LoadWallet loads an HD wallet's derived addresses.
func (m *HDWalletDetailModel) LoadWallet(primaryAddr string) tea.Cmd {
	m.loading = true
	m.primaryAddr = primaryAddr
	m.wallet = nil
	m.derived = nil
	m.goBack = false
	m.actionResult = ""
	m.showDerive = false

	return tea.Batch(
		m.spinner.Tick,
		m.loadWalletData(primaryAddr),
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

func (m *HDWalletDetailModel) loadWalletData(primaryAddr string) tea.Cmd {
	return func() tea.Msg {
		resp, err := m.hdwallets_svc.ListDerived(m.ctx, primaryAddr)
		if err != nil {
			return HDWalletDetailDataMsg{Err: err}
		}

		wallet := &evm.HDWalletResponse{
			PrimaryAddress: primaryAddr,
			DerivedCount:   len(resp.Derived),
		}

		return HDWalletDetailDataMsg{
			Wallet:  wallet,
			Derived: resp.Derived,
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

// Update handles messages.
func (m *HDWalletDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case HDWalletDetailDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.wallet = msg.Wallet
			m.derived = msg.Derived
			m.err = nil
		}
		return m, nil

	case HDWalletDeriveMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.resetDeriveForm()
			return m, m.LoadWallet(m.primaryAddr)
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
		if m.showDerive {
			return m.handleDeriveInput(msg)
		}

		switch msg.String() {
		case "esc", "backspace":
			m.goBack = true
			return m, nil
		case "d":
			m.showDerive = true
			m.deriveMode = "single"
			m.actionResult = ""
			m.indexInput.Focus()
			return m, textinput.Blink
		case "b":
			m.showDerive = true
			m.deriveMode = "batch"
			m.activeField = "start"
			m.actionResult = ""
			m.startInput.Focus()
			return m, textinput.Blink
		case "r":
			if m.primaryAddr != "" {
				return m, m.LoadWallet(m.primaryAddr)
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

// View renders the HD wallet detail view.
func (m *HDWalletDetailModel) View() string {
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
	helpText := "d: derive single | b: batch derive | Esc: back | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

// IsCapturingInput returns true when this view is capturing keyboard input (derive form active).
func (m *HDWalletDetailModel) IsCapturingInput() bool {
	return m.showDerive
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
