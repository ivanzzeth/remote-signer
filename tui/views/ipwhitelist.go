package views

import (
	"context"
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/acls"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// IPWhitelistDataMsg is sent when IP whitelist config is loaded.
type IPWhitelistDataMsg struct {
	Data *acls.IPWhitelistResponse
	Err  error
}

// IPWhitelistModel represents the IP whitelist read-only view (admin only).
type IPWhitelistModel struct {
	aclsSvc ACLsAPI
	ctx     context.Context
	width   int
	height  int
	spinner spinner.Model
	loading bool
	err     error
	data    *acls.IPWhitelistResponse
}

// ACLsAPI is the interface for fetching IP whitelist (read-only).
type ACLsAPI interface {
	GetIPWhitelist(ctx context.Context) (*acls.IPWhitelistResponse, error)
}

// NewIPWhitelistModel creates a new IP whitelist model.
func NewIPWhitelistModel(c *client.Client, ctx context.Context) (*IPWhitelistModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	return newIPWhitelistModelFromService(c.ACLs, ctx)
}

func newIPWhitelistModelFromService(svc ACLsAPI, ctx context.Context) (*IPWhitelistModel, error) {
	if svc == nil {
		return nil, fmt.Errorf("acls service is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	return &IPWhitelistModel{
		aclsSvc: svc,
		ctx:     ctx,
		spinner: s,
		loading: true,
	}, nil
}

// Init initializes the IP whitelist view.
func (m *IPWhitelistModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size.
func (m *IPWhitelistModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh reloads IP whitelist data.
func (m *IPWhitelistModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// IsCapturingInput returns false.
func (m *IPWhitelistModel) IsCapturingInput() bool {
	return false
}

func (m *IPWhitelistModel) loadData() tea.Cmd {
	return func() tea.Msg {
		data, err := m.aclsSvc.GetIPWhitelist(m.ctx)
		return IPWhitelistDataMsg{Data: data, Err: err}
	}
}

// Update handles messages.
func (m *IPWhitelistModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case IPWhitelistDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
			m.data = nil
		} else {
			m.data = msg.Data
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
	}

	return m, nil
}

// View renders the IP whitelist page.
func (m *IPWhitelistModel) View() string {
	if m.loading {
		return lipgloss.Place(
			m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			fmt.Sprintf("%s Loading IP whitelist...", m.spinner.View()),
		)
	}

	if m.err != nil {
		errBox := styles.BoxStyle.
			BorderForeground(styles.ErrorColor).
			Render(fmt.Sprintf("Error: %v\n\nPress 'r' to retry", m.err))
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, errBox)
	}

	var sections []string

	sections = append(sections, styles.SubtitleStyle.Render("IP Whitelist"))
	sections = append(sections, "")
	sections = append(sections, styles.MutedColor.Render("Read-only configuration (admin only). Changes require server config reload."))
	sections = append(sections, "")

	// Status
	status := styles.ErrorStyle.Render("Disabled")
	if m.data.Enabled {
		status = styles.SuccessStyle.Render("Enabled")
	}
	sections = append(sections, fmt.Sprintf("  Status:    %s", status))
	sections = append(sections, fmt.Sprintf("  Trust proxy: %v", m.data.TrustProxy))
	sections = append(sections, "")

	// Allowed IPs
	sections = append(sections, styles.SubtitleStyle.Render("Allowed IPs / CIDRs"))
	sections = append(sections, "")
	if len(m.data.AllowedIPs) == 0 {
		sections = append(sections, styles.MutedColor.Render("  (none)"))
	} else {
		for _, ip := range m.data.AllowedIPs {
			sections = append(sections, "  "+ip)
		}
	}
	sections = append(sections, "")

	// Trusted proxies (if trust_proxy is true)
	if m.data.TrustProxy && len(m.data.TrustedProxies) > 0 {
		sections = append(sections, styles.SubtitleStyle.Render("Trusted Proxies"))
		sections = append(sections, "")
		for _, p := range m.data.TrustedProxies {
			sections = append(sections, "  "+p)
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, sections...) + "\n\n" +
		styles.MutedColor.Render("r: refresh")
}
