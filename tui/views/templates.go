package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/templates"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// TemplatesModel represents the templates list view.
type TemplatesModel struct {
	svc         templates.API
	ctx         context.Context
	width       int
	height      int
	spinner     spinner.Model
	loading     bool
	err         error
	templates   []templates.Template
	total       int
	selectedIdx int
	offset      int
	limit       int
}

// TemplatesDataMsg is sent when templates data is loaded.
type TemplatesDataMsg struct {
	Templates []templates.Template
	Total     int
	Err       error
}

// NewTemplatesModel creates a new templates model.
func NewTemplatesModel(c *client.Client, ctx context.Context) (*TemplatesModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	if c.Templates == nil {
		return nil, fmt.Errorf("templates service is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	return &TemplatesModel{
		svc:     c.Templates,
		ctx:     ctx,
		spinner: s,
		loading: true,
		limit:   50,
	}, nil
}

// Init initializes the templates view.
func (m *TemplatesModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size.
func (m *TemplatesModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh refreshes the templates data.
func (m *TemplatesModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

func (m *TemplatesModel) loadData() tea.Cmd {
	return func() tea.Msg {
		filter := &templates.ListFilter{
			Limit:  m.limit,
			Offset: m.offset,
		}
		resp, err := m.svc.List(m.ctx, filter)
		if err != nil {
			return TemplatesDataMsg{Err: err}
		}
		return TemplatesDataMsg{Templates: resp.Templates, Total: resp.Total, Err: nil}
	}
}

// Update handles messages.
func (m *TemplatesModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case TemplatesDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.templates = msg.Templates
			m.total = msg.Total
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
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.selectedIdx < len(m.templates)-1 {
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
			if m.selectedIdx >= len(m.templates) {
				m.selectedIdx = len(m.templates) - 1
			}
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			return m, nil
		case "home", "g":
			m.selectedIdx = 0
			return m, nil
		case "end", "G":
			if len(m.templates) > 0 {
				m.selectedIdx = len(m.templates) - 1
			}
			return m, nil
		case "n":
			if m.offset+m.limit < m.total {
				m.offset += m.limit
				m.selectedIdx = 0
				return m, m.Refresh()
			}
			return m, nil
		case "p":
			if m.offset > 0 {
				m.offset -= m.limit
				if m.offset < 0 {
					m.offset = 0
				}
				m.selectedIdx = 0
				return m, m.Refresh()
			}
			return m, nil
		}
	}

	return m, nil
}

// View renders the templates view.
func (m *TemplatesModel) View() string {
	if m.loading {
		return lipgloss.Place(
			m.width,
			m.height,
			lipgloss.Center,
			lipgloss.Center,
			fmt.Sprintf("%s Loading templates...", m.spinner.View()),
		)
	}

	if m.err != nil {
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

	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Rule Templates"))
	content.WriteString("\n\n")

	headerRow := fmt.Sprintf("%-36s  %-28s  %-20s  %-12s  %-8s",
		"ID", "Name", "Type", "Source", "Enabled")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	if len(m.templates) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No templates found"))
	} else {
		for i, t := range m.templates {
			row := m.renderTemplateRow(t, i == m.selectedIdx)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	content.WriteString("\n")
	startIdx := m.offset + 1
	endIdx := m.offset + len(m.templates)
	if endIdx > m.total {
		endIdx = m.total
	}
	if len(m.templates) == 0 {
		startIdx = 0
		endIdx = 0
	}
	content.WriteString(styles.MutedColor.Render(fmt.Sprintf("Showing %d-%d of %d", startIdx, endIdx, m.total)))
	content.WriteString("\n\n")
	content.WriteString(styles.HelpStyle.Render("↑/↓: navigate | n/p: next/prev page | r: refresh"))

	return content.String()
}

func (m *TemplatesModel) renderTemplateRow(t templates.Template, selected bool) string {
	id := t.ID
	if len(id) > 36 {
		id = id[:33] + "..."
	}
	name := t.Name
	if len(name) > 28 {
		name = name[:25] + "..."
	}
	typ := t.Type
	if len(typ) > 20 {
		typ = typ[:17] + "..."
	}
	src := t.Source
	if len(src) > 12 {
		src = src[:9] + "..."
	}
	enabled := "Yes"
	if !t.Enabled {
		enabled = "No"
	}
	row := fmt.Sprintf("%-36s  %-28s  %-20s  %-12s  %-8s",
		id, name, typ, src, enabled)
	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}
	enabledStyle := styles.SuccessStyle
	if !t.Enabled {
		enabledStyle = styles.MutedColor
	}
	row = fmt.Sprintf("%-36s  %-28s  %-20s  %-12s  %s",
		id, name, typ, src, enabledStyle.Render(enabled))
	return styles.TableRowStyle.Render(row)
}

// IsCapturingInput returns false; templates view has no text input.
func (m *TemplatesModel) IsCapturingInput() bool {
	return false
}
