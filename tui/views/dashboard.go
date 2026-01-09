package views

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// DashboardData holds the data for the dashboard
type DashboardData struct {
	Health        *client.HealthResponse
	RequestCounts map[string]int
	TotalRequests int
	TotalRules    int
	LastRefresh   time.Time
}

// DashboardModel represents the dashboard view
type DashboardModel struct {
	client    *client.Client
	ctx       context.Context
	width     int
	height    int
	spinner   spinner.Model
	loading   bool
	err       error
	data      *DashboardData
	connected bool
}

// DashboardDataMsg is sent when dashboard data is loaded
type DashboardDataMsg struct {
	Data *DashboardData
	Err  error
}

// NewDashboardModel creates a new dashboard model
func NewDashboardModel(c *client.Client, ctx context.Context) (*DashboardModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	return &DashboardModel{
		client:  c,
		ctx:     ctx,
		spinner: s,
		loading: true,
	}, nil
}

// Init initializes the dashboard
func (m *DashboardModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size
func (m *DashboardModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh refreshes the dashboard data
func (m *DashboardModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

func (m *DashboardModel) loadData() tea.Cmd {
	return func() tea.Msg {
		data := &DashboardData{
			RequestCounts: make(map[string]int),
			LastRefresh:   time.Now(),
		}

		// Get health
		health, err := m.client.Health(m.ctx)
		if err != nil {
			return DashboardDataMsg{Data: nil, Err: fmt.Errorf("health check failed: %w", err)}
		}
		data.Health = health

		// Get request counts by status
		statuses := []string{"pending", "authorizing", "signing", "completed", "rejected", "failed"}
		for _, status := range statuses {
			resp, err := m.client.ListRequests(m.ctx, status, "", "", 1, 0)
			if err != nil {
				data.RequestCounts[status] = 0
				continue
			}
			data.RequestCounts[status] = resp.Total
			data.TotalRequests += resp.Total
		}

		// Get total rules
		rulesResp, err := m.client.ListRules(m.ctx, &client.ListRulesFilter{Limit: 1})
		if err == nil {
			data.TotalRules = rulesResp.Total
		}

		return DashboardDataMsg{Data: data, Err: nil}
	}
}

// Update handles messages
func (m *DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case DashboardDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
			m.connected = false
		} else {
			m.data = msg.Data
			m.err = nil
			m.connected = true
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
		}
	}

	return m, nil
}

// View renders the dashboard
func (m *DashboardModel) View() string {
	if m.loading {
		return m.renderLoading()
	}

	if m.err != nil {
		return m.renderError()
	}

	return m.renderDashboard()
}

func (m *DashboardModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading dashboard...", m.spinner.View()),
	)
}

func (m *DashboardModel) renderError() string {
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

func (m *DashboardModel) renderDashboard() string {
	var sections []string

	// Status section
	statusBox := m.renderStatusSection()
	sections = append(sections, statusBox)

	// Request counts section
	requestsBox := m.renderRequestsSection()
	sections = append(sections, requestsBox)

	// Rules section
	rulesBox := m.renderRulesSection()
	sections = append(sections, rulesBox)

	// Join sections horizontally if there's room
	topRow := lipgloss.JoinHorizontal(lipgloss.Top, statusBox, "  ", requestsBox)

	// Footer with refresh info
	footer := styles.MutedColor.Render(fmt.Sprintf(
		"Last refreshed: %s | Press 'r' to refresh",
		m.data.LastRefresh.Format("15:04:05"),
	))

	return lipgloss.JoinVertical(lipgloss.Left,
		topRow,
		"",
		rulesBox,
		"",
		footer,
	)
}

func (m *DashboardModel) renderStatusSection() string {
	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Service Status"))
	content.WriteString("\n\n")

	// Connection status
	if m.connected {
		content.WriteString(styles.SuccessStyle.Render("● Connected"))
	} else {
		content.WriteString(styles.ErrorStyle.Render("● Disconnected"))
	}
	content.WriteString("\n\n")

	// Health info
	if m.data != nil && m.data.Health != nil {
		content.WriteString(fmt.Sprintf("Status:  %s\n", styles.GetStatusStyle("completed").Render(m.data.Health.Status)))
		content.WriteString(fmt.Sprintf("Version: %s", m.data.Health.Version))
	}

	return styles.BoxStyle.Width(30).Render(content.String())
}

func (m *DashboardModel) renderRequestsSection() string {
	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Request Summary"))
	content.WriteString("\n\n")

	if m.data == nil {
		content.WriteString("No data available")
		return styles.BoxStyle.Width(40).Render(content.String())
	}

	// Request counts by status
	statuses := []struct {
		key   string
		label string
	}{
		{"pending", "Pending"},
		{"authorizing", "Authorizing"},
		{"signing", "Signing"},
		{"completed", "Completed"},
		{"rejected", "Rejected"},
		{"failed", "Failed"},
	}

	for _, s := range statuses {
		count := m.data.RequestCounts[s.key]
		countStr := styles.GetStatusStyle(s.key).Render(fmt.Sprintf("%d", count))
		content.WriteString(fmt.Sprintf("%-12s %s\n", s.label+":", countStr))
	}

	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("Total:       %d", m.data.TotalRequests))

	return styles.BoxStyle.Width(40).Render(content.String())
}

func (m *DashboardModel) renderRulesSection() string {
	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Rules"))
	content.WriteString("\n\n")

	if m.data == nil {
		content.WriteString("No data available")
		return styles.BoxStyle.Width(30).Render(content.String())
	}

	content.WriteString(fmt.Sprintf("Total Rules: %d", m.data.TotalRules))

	return styles.BoxStyle.Width(30).Render(content.String())
}
