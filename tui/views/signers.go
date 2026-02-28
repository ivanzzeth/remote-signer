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

	// Create signer state
	showCreate       bool
	createStep       int // 0: select type, 1: enter password
	selectedType     string
	passwordInput    textinput.Model
	confirmInput     textinput.Model
	showPassword     bool
	actionResult     string
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

// NewSignersModel creates a new signers model
func NewSignersModel(c *client.Client, ctx context.Context) (*SignersModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newSignersModelFromService(c.EVM.Signers, ctx)
}

// newSignersModelFromService creates a signers model from a SignerAPI (for testing).
func newSignersModelFromService(svc evm.SignerAPI, ctx context.Context) (*SignersModel, error) {
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

	return &SignersModel{
		signers_svc:   svc,
		ctx:           ctx,
		spinner:       s,
		loading:       true,
		limit:         20,
		filterInput:   ti,
		passwordInput: pwInput,
		confirmInput:  confirmInput,
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
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.showCreate = false
			m.createStep = 0
			m.selectedType = ""
			m.passwordInput.SetValue("")
			m.confirmInput.SetValue("")
			// Refresh the list
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

func (m *SignersModel) handleCreateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.createStep {
	case 0: // Select type
		switch msg.String() {
		case "1":
			m.selectedType = "keystore"
			m.createStep = 1
			m.passwordInput.Focus()
			return m, textinput.Blink
		case "esc":
			m.showCreate = false
			m.createStep = 0
			return m, nil
		}
	case 1: // Enter password
		switch msg.String() {
		case "enter":
			if m.passwordInput.Value() != "" {
				m.createStep = 2
				m.confirmInput.Focus()
				m.passwordInput.Blur()
				return m, textinput.Blink
			}
			return m, nil
		case "esc":
			m.showCreate = false
			m.createStep = 0
			m.passwordInput.SetValue("")
			m.passwordInput.Blur()
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
	case 2: // Confirm password
		switch msg.String() {
		case "enter":
			if m.confirmInput.Value() == m.passwordInput.Value() {
				// Passwords match, create signer
				m.loading = true
				m.confirmInput.Blur()
				return m, tea.Batch(m.spinner.Tick, m.createSigner(m.selectedType, m.passwordInput.Value()))
			}
			m.actionResult = styles.ErrorStyle.Render("Passwords do not match")
			return m, nil
		case "esc":
			m.showCreate = false
			m.createStep = 0
			m.passwordInput.SetValue("")
			m.confirmInput.SetValue("")
			m.passwordInput.Blur()
			m.confirmInput.Blur()
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
	return m, nil
}

// View renders the signers view
func (m *SignersModel) View() string {
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
		content.WriteString(styles.ButtonStyle.Render(" [1] Keystore "))
		content.WriteString("\n\n")
		content.WriteString(styles.MutedColor.Render("Press number to select, Esc to cancel"))

	case 1:
		content.WriteString(fmt.Sprintf("Type: %s\n\n", styles.HighlightStyle.Render(m.selectedType)))
		content.WriteString(styles.SubtitleStyle.Render("Enter Password:"))
		content.WriteString("\n\n")
		content.WriteString(m.passwordInput.View())
		content.WriteString("\n\n")
		if m.showPassword {
			content.WriteString(styles.MutedColor.Render("Tab: hide password | Enter: continue | Esc: cancel"))
		} else {
			content.WriteString(styles.MutedColor.Render("Tab: show password | Enter: continue | Esc: cancel"))
		}

	case 2:
		content.WriteString(fmt.Sprintf("Type: %s\n\n", styles.HighlightStyle.Render(m.selectedType)))
		content.WriteString(styles.SubtitleStyle.Render("Confirm Password:"))
		content.WriteString("\n\n")
		content.WriteString(m.confirmInput.View())
		content.WriteString("\n\n")
		if m.actionResult != "" {
			content.WriteString(m.actionResult)
			content.WriteString("\n\n")
		}
		if m.showPassword {
			content.WriteString(styles.MutedColor.Render("Tab: hide password | Enter: create | Esc: cancel"))
		} else {
			content.WriteString(styles.MutedColor.Render("Tab: show password | Enter: create | Esc: cancel"))
		}
	}

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
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
	headerRow := fmt.Sprintf("%-44s  %-14s  %-8s",
		"Address", "Type", "Enabled")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	// Rows
	if len(m.signers) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No signers found"))
	} else {
		for i, signer := range m.signers {
			row := m.renderSignerRow(signer, i == m.selectedIdx)
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
	helpText := "up/down: navigate | +/a: create signer | f: filter | c: clear | n/p: next/prev | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *SignersModel) renderSignerRow(signer evm.Signer, selected bool) string {
	// Format address
	address := signer.Address
	if len(address) > 44 {
		address = address[:41] + "..."
	}

	enabled := "Yes"
	if !signer.Enabled {
		enabled = "No"
	}

	row := fmt.Sprintf("%-44s  %-14s  %-8s",
		address,
		signer.Type,
		enabled,
	)

	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}

	// Color type
	typeStyle := styles.MutedColor
	if signer.Type == "private_key" {
		typeStyle = styles.WarningStyle
	} else if signer.Type == "keystore" {
		typeStyle = styles.SuccessStyle
	}
	typePart := typeStyle.Render(fmt.Sprintf("%-14s", signer.Type))

	// Color enabled
	enabledStyle := styles.SuccessStyle
	if !signer.Enabled {
		enabledStyle = styles.MutedColor
	}
	enabledPart := enabledStyle.Render(fmt.Sprintf("%-8s", enabled))

	row = fmt.Sprintf("%-44s  %s  %s",
		address,
		typePart,
		enabledPart,
	)

	return styles.TableRowStyle.Render(row)
}
