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

// PresetDetailModel shows a single preset's vars and allows Apply.
type PresetDetailModel struct {
	svc       *presets.Service
	ctx       context.Context
	width     int
	height    int
	presetID  string
	hints     []string
	spinner   spinner.Model
	loading   bool
	applying  bool
	err       error
	success   string
	goBack    bool
}

// PresetVarsMsg is sent when vars are loaded.
type PresetVarsMsg struct {
	Hints []string
	Err   error
}

// PresetApplyMsg is sent when apply completes.
type PresetApplyMsg struct {
	Count int
	Err   error
}

// NewPresetDetailModel creates a preset detail model.
func NewPresetDetailModel(c *client.Client, ctx context.Context) (*PresetDetailModel, error) {
	if c == nil || c.Presets == nil || ctx == nil {
		return nil, fmt.Errorf("client and context required")
	}
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle
	return &PresetDetailModel{
		svc:     c.Presets,
		ctx:     ctx,
		spinner: s,
	}, nil
}

// Init is required by tea.Model; no-op for this view.
func (m *PresetDetailModel) Init() tea.Cmd {
	return nil
}

// SetSize sets the view size.
func (m *PresetDetailModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// LoadPreset loads vars for the given preset ID.
func (m *PresetDetailModel) LoadPreset(id string) tea.Cmd {
	m.presetID = id
	m.loading = true
	m.err = nil
	m.success = ""
	m.goBack = false
	return tea.Batch(
		m.spinner.Tick,
		m.loadVars(id),
	)
}

func (m *PresetDetailModel) loadVars(id string) tea.Cmd {
	return func() tea.Msg {
		resp, err := m.svc.Vars(m.ctx, id)
		if err != nil {
			return PresetVarsMsg{Err: err}
		}
		return PresetVarsMsg{Hints: resp.OverrideHints, Err: nil}
	}
}

// Apply runs preset apply (with empty variables for now).
func (m *PresetDetailModel) Apply() tea.Cmd {
	if m.presetID == "" || m.applying {
		return nil
	}
	m.applying = true
	m.err = nil
	m.success = ""
	id := m.presetID
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			resp, err := m.svc.Apply(m.ctx, id, &presets.ApplyRequest{})
			if err != nil {
				return PresetApplyMsg{Err: err}
			}
			return PresetApplyMsg{Count: len(resp.Results), Err: nil}
		},
	)
}

// ShouldGoBack returns true when the view should close (e.g. after success or user Esc).
func (m *PresetDetailModel) ShouldGoBack() bool {
	return m.goBack
}

// ResetGoBack clears the go-back flag.
func (m *PresetDetailModel) ResetGoBack() {
	m.goBack = false
}

// Update handles messages.
func (m *PresetDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case PresetVarsMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.hints = msg.Hints
			m.err = nil
		}
		return m, nil

	case PresetApplyMsg:
		m.applying = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.err = nil
			m.success = fmt.Sprintf("Applied preset: %d rule(s) created.", msg.Count)
			m.goBack = true
		}
		return m, nil

	case spinner.TickMsg:
		if m.loading || m.applying {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "backspace":
			m.goBack = true
			return m, nil
		case "a":
			if m.presetID != "" && !m.loading && !m.applying {
				return m, m.Apply()
			}
			return m, nil
		}
	}

	return m, nil
}

// View renders the preset detail view.
func (m *PresetDetailModel) View() string {
	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Preset: " + m.presetID))
	content.WriteString("\n\n")

	if m.loading {
		content.WriteString(fmt.Sprintf("%s Loading variables...", m.spinner.View()))
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content.String())
	}

	if m.applying {
		content.WriteString(fmt.Sprintf("%s Applying preset...", m.spinner.View()))
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content.String())
	}

	if m.err != nil {
		content.WriteString(styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.err)))
		content.WriteString("\n\n")
		content.WriteString(styles.HelpStyle.Render("Esc: back"))
		return styles.BoxStyle.Render(content.String())
	}

	if m.success != "" {
		content.WriteString(styles.SuccessStyle.Render(m.success))
		content.WriteString("\n\n")
		content.WriteString(styles.HelpStyle.Render("Esc: back to list"))
		return styles.BoxStyle.Render(content.String())
	}

	content.WriteString(styles.MutedColor.Render("Variable override hints (apply uses defaults if not provided):"))
	content.WriteString("\n\n")
	if len(m.hints) == 0 {
		content.WriteString(styles.MutedColor.Render("  (none)"))
	} else {
		for _, h := range m.hints {
			content.WriteString("  • ")
			content.WriteString(h)
			content.WriteString("\n")
		}
	}

	content.WriteString("\n\n")
	content.WriteString(styles.ButtonStyle.Render(" [a] Apply preset (create rules) "))
	content.WriteString("  ")
	content.WriteString(styles.HelpStyle.Render("Esc: back"))

	return styles.BoxStyle.Render(content.String())
}

// IsCapturingInput returns false.
func (m *PresetDetailModel) IsCapturingInput() bool {
	return false
}
