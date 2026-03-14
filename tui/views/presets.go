package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/presets"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// PresetsModel represents the presets list view.
type PresetsModel struct {
	svc         *presets.Service
	ctx         context.Context
	width       int
	height      int
	spinner     spinner.Model
	loading     bool
	err         error
	presets     []presets.PresetEntry
	selectedIdx int
	openDetail  bool
}

// PresetsDataMsg is sent when presets data is loaded.
type PresetsDataMsg struct {
	Presets []presets.PresetEntry
	Err     error
}

// NewPresetsModel creates a new presets model.
func NewPresetsModel(c *client.Client, ctx context.Context) (*PresetsModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	if c.Presets == nil {
		return nil, fmt.Errorf("presets service is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	return &PresetsModel{
		svc:     c.Presets,
		ctx:     ctx,
		spinner: s,
		loading: true,
	}, nil
}

// Init initializes the presets view.
func (m *PresetsModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size.
func (m *PresetsModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh refreshes the presets data.
func (m *PresetsModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

func (m *PresetsModel) loadData() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.svc.List(m.ctx)
		if err != nil {
			return PresetsDataMsg{Err: err}
		}
		return PresetsDataMsg{Presets: resp.Presets, Err: nil}
	}
}

// GetSelectedPresetID returns the ID of the selected preset, or "" if none.
func (m *PresetsModel) GetSelectedPresetID() string {
	if len(m.presets) == 0 || m.selectedIdx < 0 || m.selectedIdx >= len(m.presets) {
		return ""
	}
	return m.presets[m.selectedIdx].ID
}

// ShouldOpenDetail returns true when the user requested to open preset detail (e.g. Enter).
func (m *PresetsModel) ShouldOpenDetail() bool {
	return m.openDetail
}

// ResetOpenDetail clears the open-detail flag.
func (m *PresetsModel) ResetOpenDetail() {
	m.openDetail = false
}

// Update handles messages.
func (m *PresetsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case PresetsDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.presets = msg.Presets
			m.err = nil
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
		switch msg.String() {
		case "r":
			return m, m.Refresh()
		case "enter":
			if len(m.presets) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(m.presets) {
				m.openDetail = true
			}
			return m, nil
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.selectedIdx < len(m.presets)-1 {
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
			if m.selectedIdx >= len(m.presets) {
				m.selectedIdx = len(m.presets) - 1
			}
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			return m, nil
		case "home", "g":
			m.selectedIdx = 0
			return m, nil
		case "end", "G":
			if len(m.presets) > 0 {
				m.selectedIdx = len(m.presets) - 1
			}
			return m, nil
		}
	}

	return m, nil
}

// View renders the presets view.
func (m *PresetsModel) View() string {
	if m.loading {
		return lipgloss.Place(
			m.width,
			m.height,
			lipgloss.Center,
			lipgloss.Center,
			fmt.Sprintf("%s Loading presets...", m.spinner.View()),
		)
	}

	if m.err != nil {
		msg := m.err.Error()
		if strings.Contains(msg, "404") {
			msg = "Preset API not enabled. Set presets.dir in server config and ensure rules are mounted (e.g. Docker: ./rules:/app/rules)."
		}
		errBox := styles.BoxStyle.
			BorderForeground(styles.ErrorColor).
			Render(fmt.Sprintf("Error: %s\n\nPress 'r' to retry", msg))
		return lipgloss.Place(
			m.width,
			m.height,
			lipgloss.Center,
			lipgloss.Center,
			errBox,
		)
	}

	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Presets"))
	content.WriteString("\n\n")
	content.WriteString(styles.MutedColor.Render("Apply a preset to create rule(s) from template(s). Admin only."))
	content.WriteString("\n\n")

	headerRow := fmt.Sprintf("%-40s  %s", "ID", "Templates")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	if len(m.presets) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No presets found (add .yaml files under rules/presets/ on the server)."))
	} else {
		for i, p := range m.presets {
			row := m.renderPresetRow(p, i == m.selectedIdx)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	content.WriteString("\n\n")
	content.WriteString(styles.HelpStyle.Render("↑/↓: navigate | Enter: open detail & apply | r: refresh"))

	return content.String()
}

func (m *PresetsModel) renderPresetRow(p presets.PresetEntry, selected bool) string {
	id := p.ID
	if len(id) > 40 {
		id = id[:37] + "..."
	}
	templatesStr := strings.Join(p.TemplateNames, ", ")
	if len(templatesStr) > 50 {
		templatesStr = templatesStr[:47] + "..."
	}
	row := fmt.Sprintf("%-40s  %s", id, templatesStr)
	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}
	return styles.TableRowStyle.Render(row)
}

// IsCapturingInput returns false.
func (m *PresetsModel) IsCapturingInput() bool {
	return false
}
