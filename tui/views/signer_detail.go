package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// SignerDetailModel represents the signer detail view
type SignerDetailModel struct {
	ctx      context.Context
	width    int
	height   int
	viewport viewport.Model
	signer   *evm.Signer
	goBack   bool
	ready    bool
}

// NewSignerDetailModel creates a new signer detail model
func NewSignerDetailModel(ctx context.Context) (*SignerDetailModel, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	return &SignerDetailModel{
		ctx: ctx,
	}, nil
}

// Init initializes the view
func (m *SignerDetailModel) Init() tea.Cmd {
	return nil
}

// SetSize sets the view size
func (m *SignerDetailModel) SetSize(width, height int) {
	m.width = width
	m.height = height

	headerHeight := 3
	footerHeight := 3
	viewportHeight := height - headerHeight - footerHeight
	if viewportHeight < 1 {
		viewportHeight = 1
	}

	if !m.ready {
		m.viewport = viewport.New(width, viewportHeight)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = width
		m.viewport.Height = viewportHeight
	}
}

// LoadSigner sets the signer data to display (no API call needed)
func (m *SignerDetailModel) LoadSigner(signer evm.Signer) {
	m.signer = &signer
	m.goBack = false
}

// ShouldGoBack returns true if the view should go back to the list
func (m *SignerDetailModel) ShouldGoBack() bool {
	return m.goBack
}

// ResetGoBack resets the go back flag
func (m *SignerDetailModel) ResetGoBack() {
	m.goBack = false
}

// IsCapturingInput returns false (read-only view, no forms)
func (m *SignerDetailModel) IsCapturingInput() bool {
	return false
}

// Update handles messages
func (m *SignerDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "backspace":
			m.goBack = true
			return m, nil
		case "up", "k":
			m.viewport.LineUp(1)
			return m, nil
		case "down", "j":
			m.viewport.LineDown(1)
			return m, nil
		case "pgup", "ctrl+u":
			m.viewport.HalfViewUp()
			return m, nil
		case "pgdown", "ctrl+d":
			m.viewport.HalfViewDown()
			return m, nil
		case "home", "g":
			m.viewport.GotoTop()
			return m, nil
		case "end", "G":
			m.viewport.GotoBottom()
			return m, nil
		}
	}

	return m, nil
}

// View renders the signer detail view
func (m *SignerDetailModel) View() string {
	if m.signer == nil {
		return "No signer loaded"
	}

	return m.renderDetail()
}

func (m *SignerDetailModel) renderDetail() string {
	var content strings.Builder

	// Basic info
	enabledStr := "Enabled"
	enabledStyle := styles.SuccessStyle
	if !m.signer.Enabled {
		enabledStr = "Disabled"
		enabledStyle = styles.MutedColor
	}

	lockedStr := "Ready"
	lockedStyle := styles.SuccessStyle
	if m.signer.Locked {
		lockedStr = "Locked"
		lockedStyle = styles.WarningStyle
	}

	info := []struct {
		key   string
		value string
		style lipgloss.Style
	}{
		{"Address", m.signer.Address, lipgloss.NewStyle()},
		{"Type", m.signer.Type, lipgloss.NewStyle()},
		{"Lock State", lockedStr, lockedStyle},
		{"Enabled", enabledStr, enabledStyle},
	}

	for _, item := range info {
		keyStr := styles.InfoKeyStyle.Render(item.key + ":")
		valueStr := item.style.Render(item.value)
		content.WriteString(fmt.Sprintf("%s %s\n", keyStr, valueStr))
	}

	// Ownership section
	if m.signer.OwnerID != "" {
		content.WriteString("\n")
		content.WriteString(styles.SubtitleStyle.Render("Ownership"))
		content.WriteString("\n")
		ownerLine := fmt.Sprintf("  Owner: %s  Status: %s", m.signer.OwnerID, m.signer.Status)
		content.WriteString(styles.TableRowStyle.Render(ownerLine))
		content.WriteString("\n")
	}

	// Set content in viewport
	m.viewport.SetContent(content.String())

	// Build final view with header, viewport, and footer
	var view strings.Builder

	// Header
	view.WriteString(styles.TitleStyle.Render("Signer Detail"))
	view.WriteString("\n\n")

	// Viewport (scrollable content)
	view.WriteString(m.viewport.View())
	view.WriteString("\n")

	// Footer with scroll info and help
	scrollInfo := fmt.Sprintf("(%d%% scrolled)", int(m.viewport.ScrollPercent()*100))
	helpText := "j/k: scroll | Esc: back | CLI: signer access grant/revoke/list"
	view.WriteString(styles.HelpStyle.Render(fmt.Sprintf("%s  %s", scrollInfo, helpText)))

	return view.String()
}
