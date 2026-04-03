package views

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/apikeys"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// APIKeysDataMsg is sent when API keys data is loaded.
type APIKeysDataMsg struct {
	Keys  []apikeys.APIKey
	Total int
	Err   error
}

// APIKeysModel represents the API keys list and detail view.
type APIKeysModel struct {
	apikeysSvc apikeys.API
	ctx         context.Context
	width       int
	height      int
	spinner     spinner.Model
	loading     bool
	err         error
	keys        []apikeys.APIKey
	total       int
	selectedIdx int
	offset      int
	limit       int
	sourceFilter string
	showFilter   bool
	filterInput  textinput.Model

	// Detail view state
	showDetail bool
	viewport   viewport.Model
	vpReady    bool
}

// NewAPIKeysModel creates a new API keys model.
func NewAPIKeysModel(c *client.Client, ctx context.Context) (*APIKeysModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newAPIKeysModelFromService(c.APIKeys, ctx)
}

// newAPIKeysModelFromService creates an API keys model from an API interface (for testing).
func newAPIKeysModelFromService(svc apikeys.API, ctx context.Context) (*APIKeysModel, error) {
	if svc == nil {
		return nil, fmt.Errorf("apikeys service is required")
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

	return &APIKeysModel{
		apikeysSvc: svc,
		ctx:         ctx,
		spinner:     s,
		loading:     true,
		limit:       20,
		filterInput: ti,
	}, nil
}

// Init initializes the API keys view.
func (m *APIKeysModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size.
func (m *APIKeysModel) SetSize(width, height int) {
	m.width = width
	m.height = height

	// Update viewport if in detail view
	headerHeight := 3
	footerHeight := 3
	vpHeight := height - headerHeight - footerHeight
	vpHeight = max(vpHeight, 1)
	if !m.vpReady {
		m.viewport = viewport.New(width, vpHeight)
		m.viewport.Style = lipgloss.NewStyle()
		m.vpReady = true
	} else {
		m.viewport.Width = width
		m.viewport.Height = vpHeight
	}
}

// Refresh refreshes the API keys data.
func (m *APIKeysModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// IsCapturingInput returns true when this view is capturing keyboard input.
func (m *APIKeysModel) IsCapturingInput() bool {
	return m.showFilter
}

func (m *APIKeysModel) loadData() tea.Cmd {
	return func() tea.Msg {
		filter := &apikeys.ListFilter{
			Source: m.sourceFilter,
			Limit:  m.limit,
			Offset: m.offset,
		}

		resp, err := m.apikeysSvc.List(m.ctx, filter)
		if err != nil {
			return APIKeysDataMsg{Err: err}
		}
		return APIKeysDataMsg{Keys: resp.Keys, Total: resp.Total}
	}
}

// hasMore returns true if there are more pages available.
func (m *APIKeysModel) hasMore() bool {
	return m.offset+m.limit < m.total
}

// getSelectedKey returns the currently selected API key, or nil if none selected.
func (m *APIKeysModel) getSelectedKey() *apikeys.APIKey {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.keys) {
		return nil
	}
	return &m.keys[m.selectedIdx]
}

// Update handles messages.
func (m *APIKeysModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case APIKeysDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.keys = msg.Keys
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
		// Detail view key handling
		if m.showDetail {
			return m.handleDetailInput(msg)
		}

		// Filter input handling
		if m.showFilter {
			return m.handleFilterInput(msg)
		}

		// Normal list key handling
		return m.handleListInput(msg)
	}

	return m, nil
}

func (m *APIKeysModel) handleDetailInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "backspace":
		m.showDetail = false
		return m, nil
	case "up", "k":
		m.viewport.ScrollUp(1)
		return m, nil
	case "down", "j":
		m.viewport.ScrollDown(1)
		return m, nil
	case "pgup", "ctrl+u":
		m.viewport.HalfPageUp()
		return m, nil
	case "pgdown", "ctrl+d":
		m.viewport.HalfPageDown()
		return m, nil
	case "home", "g":
		m.viewport.GotoTop()
		return m, nil
	case "end", "G":
		m.viewport.GotoBottom()
		return m, nil
	}
	return m, nil
}

func (m *APIKeysModel) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.sourceFilter = m.filterInput.Value()
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

func (m *APIKeysModel) handleListInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "r":
		return m, m.Refresh()
	case "f":
		m.showFilter = true
		m.filterInput.Placeholder = "Source (config, api)"
		m.filterInput.Focus()
		return m, textinput.Blink
	case "up", "k":
		if m.selectedIdx > 0 {
			m.selectedIdx--
		}
		return m, nil
	case "down", "j":
		if m.selectedIdx < len(m.keys)-1 {
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
		if m.selectedIdx >= len(m.keys) {
			m.selectedIdx = len(m.keys) - 1
		}
		if m.selectedIdx < 0 {
			m.selectedIdx = 0
		}
		return m, nil
	case "home", "g":
		m.selectedIdx = 0
		return m, nil
	case "end", "G":
		if len(m.keys) > 0 {
			m.selectedIdx = len(m.keys) - 1
		}
		return m, nil
	case "n":
		if m.hasMore() {
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
	case "c":
		m.sourceFilter = ""
		m.filterInput.SetValue("")
		m.offset = 0
		m.selectedIdx = 0
		return m, m.Refresh()
	case "enter":
		if m.getSelectedKey() != nil {
			m.showDetail = true
			m.buildDetailContent()
		}
		return m, nil
	}
	return m, nil
}

// View renders the API keys view.
func (m *APIKeysModel) View() string {
	if m.showDetail {
		return m.renderDetail()
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

	return m.renderList()
}

func (m *APIKeysModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading API keys...", m.spinner.View()),
	)
}

func (m *APIKeysModel) renderError() string {
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

func (m *APIKeysModel) renderFilterInput() string {
	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Filter by Source"))
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

func (m *APIKeysModel) renderList() string {
	var content strings.Builder

	// Header
	header := styles.SubtitleStyle.Render("API Keys")
	if m.sourceFilter != "" {
		header += styles.MutedColor.Render(fmt.Sprintf(" (filtered: source=%s)", m.sourceFilter))
	}
	content.WriteString(header)
	content.WriteString("\n\n")

	// Read-only notice
	content.WriteString(styles.MutedColor.Render("Read-only view. Manage API keys via the server API when api_keys_api_readonly is disabled."))
	content.WriteString("\n\n")

	// Table header
	headerRow := fmt.Sprintf("%-20s  %-20s  %-8s  %-10s  %-8s  %-10s",
		"ID", "Name", "Source", "Role", "Enabled", "Rate Limit")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	// Rows
	if len(m.keys) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No API keys found"))
	} else {
		for i, k := range m.keys {
			row := m.renderKeyRow(k, i == m.selectedIdx)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	// Pagination info
	content.WriteString("\n")
	startIdx := m.offset + 1
	endIdx := m.offset + len(m.keys)
	endIdx = min(endIdx, m.total)
	if len(m.keys) == 0 {
		startIdx = 0
		endIdx = 0
	}
	pagination := fmt.Sprintf("Showing %d-%d of %d", startIdx, endIdx, m.total)
	if m.hasMore() {
		pagination += " (more available)"
	}
	content.WriteString(styles.MutedColor.Render(pagination))

	// Help
	content.WriteString("\n\n")
	helpText := "Enter: view detail | up/down: navigate | f: filter | c: clear | n/p: next/prev | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *APIKeysModel) renderKeyRow(k apikeys.APIKey, selected bool) string {
	id := k.ID
	if len(id) > 20 {
		id = id[:17] + "..."
	}

	name := k.Name
	if len(name) > 20 {
		name = name[:17] + "..."
	}

	roleStr := string(k.Role)
	if roleStr == "" {
		roleStr = "-"
	}

	enabledStr := "Yes"
	if !k.Enabled {
		enabledStr = "No"
	}

	rateLimitStr := fmt.Sprintf("%d", k.RateLimit)
	if k.RateLimit == 0 {
		rateLimitStr = "unlimited"
	}

	row := fmt.Sprintf("%-20s  %-20s  %-8s  %-10s  %-8s  %-10s",
		id, name, k.Source, roleStr, enabledStr, rateLimitStr)

	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}

	// Color source
	sourceStyle := styles.MutedColor
	switch k.Source {
	case "config":
		sourceStyle = styles.WarningStyle
	case "api":
		sourceStyle = styles.SuccessStyle
	}
	sourcePart := sourceStyle.Render(fmt.Sprintf("%-8s", k.Source))

	// Color role
	roleStyle := styles.MutedColor
	if k.Role == "admin" {
		roleStyle = lipgloss.NewStyle().Foreground(styles.ErrorColor).Bold(true)
	}
	rolePart := roleStyle.Render(fmt.Sprintf("%-10s", roleStr))

	// Color enabled
	enabledStyle := styles.SuccessStyle
	if !k.Enabled {
		enabledStyle = styles.MutedColor
	}
	enabledPart := enabledStyle.Render(fmt.Sprintf("%-8s", enabledStr))

	coloredRow := fmt.Sprintf("%-20s  %-20s  %s  %s  %s  %-10s",
		id, name, sourcePart, rolePart, enabledPart, rateLimitStr)
	return styles.TableRowStyle.Render(coloredRow)
}

func (m *APIKeysModel) buildDetailContent() {
	k := m.getSelectedKey()
	if k == nil {
		return
	}

	var content strings.Builder

	// Basic info
	info := []struct {
		key   string
		value string
		style lipgloss.Style
	}{
		{"ID", k.ID, lipgloss.NewStyle()},
		{"Name", k.Name, lipgloss.NewStyle()},
		{"Source", k.Source, lipgloss.NewStyle()},
		{"Role", string(k.Role), lipgloss.NewStyle()},
		{"Enabled", formatBool(k.Enabled), enabledStyle(k.Enabled)},
		{"Rate Limit", formatRateLimit(k.RateLimit), lipgloss.NewStyle()},
	}

	for _, item := range info {
		keyStr := styles.InfoKeyStyle.Render(item.key + ":")
		valueStr := item.style.Render(item.value)
		content.WriteString(fmt.Sprintf("%s %s\n", keyStr, valueStr))
	}

	// Timestamps
	content.WriteString("\n")
	content.WriteString(styles.SubtitleStyle.Render("Timestamps"))
	content.WriteString("\n")

	timestamps := []struct {
		key   string
		value string
	}{
		{"Created At", k.CreatedAt.Format(time.RFC3339)},
		{"Updated At", k.UpdatedAt.Format(time.RFC3339)},
		{"Last Used At", formatOptionalTime(k.LastUsedAt)},
		{"Expires At", formatOptionalTime(k.ExpiresAt)},
	}

	for _, ts := range timestamps {
		keyStr := styles.InfoKeyStyle.Render(ts.key + ":")
		content.WriteString(fmt.Sprintf("%s %s\n", keyStr, ts.value))
	}

	// Note: signer access is now managed via signer ownership/access, not on API keys

	m.viewport.SetContent(content.String())
	m.viewport.GotoTop()
}

func (m *APIKeysModel) renderDetail() string {
	var view strings.Builder

	// Header
	view.WriteString(styles.TitleStyle.Render("API Key Detail"))
	view.WriteString("\n\n")

	// Viewport (scrollable content)
	view.WriteString(m.viewport.View())
	view.WriteString("\n")

	// Footer with scroll info and help
	scrollInfo := fmt.Sprintf("(%d%% scrolled)", int(m.viewport.ScrollPercent()*100))
	helpText := "j/k: scroll | Esc/Backspace: back"
	view.WriteString(styles.HelpStyle.Render(fmt.Sprintf("%s  %s", scrollInfo, helpText)))

	return view.String()
}

// Helper functions for detail rendering.

func formatBool(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

func formatRateLimit(v int) string {
	if v == 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d req/s", v)
}

func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return "N/A"
	}
	return t.Format(time.RFC3339)
}

func adminStyle(isAdmin bool) lipgloss.Style {
	if isAdmin {
		return lipgloss.NewStyle().Foreground(styles.ErrorColor).Bold(true)
	}
	return styles.MutedColor
}

func enabledStyle(isEnabled bool) lipgloss.Style {
	if isEnabled {
		return styles.SuccessStyle
	}
	return styles.MutedColor
}
