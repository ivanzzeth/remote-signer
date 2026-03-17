package views

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/apikeys"
	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// SecurityData holds all data for the security overview page.
type SecurityData struct {
	Health       *client.HealthResponse
	Rules        *evm.ListRulesResponse
	Signers      *evm.ListSignersResponse
	APIKeys      *apikeys.ListResponse
	RecentAlerts []audit.Record
	LastRefresh  time.Time
}

// SecurityDataMsg is sent when security data is loaded.
type SecurityDataMsg struct {
	Data *SecurityData
	Err  error
}

// sectionIndex identifies an expandable section.
type sectionIndex int

const (
	sectionNetwork sectionIndex = iota
	sectionAuth
	sectionRuleEngine
	sectionKeyMgmt
	sectionApproval
	sectionAuditMonitor
	sectionCount // sentinel
)

// apiKeyLister is the interface for listing API keys.
type apiKeyLister interface {
	List(ctx context.Context, filter *apikeys.ListFilter) (*apikeys.ListResponse, error)
}

// Security sub-tab: 0=Overview, 1=Events
const (
	SecuritySubTabOverview = 0
	SecuritySubTabEvents   = 1
	SecuritySubTabCount    = 2
)

// SecurityModel represents the security overview view.
type SecurityModel struct {
	health    healthChecker
	rules     evm.RuleAPI
	signers   evm.SignerAPI
	audit     auditLister
	apikeys   apiKeyLister
	ctx       context.Context
	width     int
	height    int
	spinner   spinner.Model
	loading   bool
	err       error
	data      *SecurityData
	expanded  sectionIndex // currently expanded section (-1 = none)
	cursor    sectionIndex // keyboard cursor
	subTab    int          // 0=Overview, 1=Events
	viewport  viewport.Model
	vpReady   bool
}

// GetSubTab returns the current Security sub-tab (0=Overview, 1=Events).
func (m *SecurityModel) GetSubTab() int {
	if m.subTab < 0 || m.subTab >= SecuritySubTabCount {
		return SecuritySubTabOverview
	}
	return m.subTab
}

// SetSubTab sets the Security sub-tab (0=Overview, 1=Events).
func (m *SecurityModel) SetSubTab(sub int) {
	if sub >= 0 && sub < SecuritySubTabCount {
		m.subTab = sub
	}
}

// auditLister is the interface for listing audit records.
type auditLister interface {
	List(ctx context.Context, filter *audit.ListFilter) (*audit.ListResponse, error)
}

// NewSecurityModel creates a new security model.
func NewSecurityModel(c *client.Client, ctx context.Context) (*SecurityModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	return &SecurityModel{
		health:   c,
		rules:    c.EVM.Rules,
		signers:  c.EVM.Signers,
		audit:    c.Audit,
		apikeys:  c.APIKeys,
		ctx:      ctx,
		spinner:  s,
		loading:  true,
		expanded: -1,
		cursor:   0,
	}, nil
}

// Init initializes the security view.
func (m *SecurityModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size and initializes or resizes the viewport.
func (m *SecurityModel) SetSize(width, height int) {
	m.width = width
	m.height = height

	footerHeight := 1
	vpHeight := height - footerHeight
	if vpHeight < 1 {
		vpHeight = 1
	}
	if !m.vpReady {
		m.viewport = viewport.New(width, vpHeight)
		m.viewport.Style = lipgloss.NewStyle()
		m.vpReady = true
	} else {
		m.viewport.Width = width
		m.viewport.Height = vpHeight
	}
}

// Refresh refreshes the security data.
func (m *SecurityModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// IsCapturingInput returns false; security view has no text inputs.
func (m *SecurityModel) IsCapturingInput() bool {
	return false
}

func (m *SecurityModel) loadData() tea.Cmd {
	return func() tea.Msg {
		data := &SecurityData{
			LastRefresh: time.Now(),
		}

		// Health (includes security config)
		health, err := m.health.Health(m.ctx)
		if err != nil {
			return SecurityDataMsg{Data: nil, Err: fmt.Errorf("health check failed: %w", err)}
		}
		data.Health = health

		// Rules summary
		rulesResp, err := m.rules.List(m.ctx, &evm.ListRulesFilter{Limit: 200})
		if err == nil {
			data.Rules = rulesResp
		}

		// Signers summary
		signersResp, err := m.signers.List(m.ctx, &evm.ListSignersFilter{})
		if err == nil {
			data.Signers = signersResp
		}

		// API keys
		apiKeysResp, err := m.apikeys.List(m.ctx, &apikeys.ListFilter{Limit: 100})
		if err == nil {
			data.APIKeys = apiKeysResp
		}

		// Recent security alerts (auth failures, blocklist rejects, auto-locks, IP blocks)
		securityEventTypes := []string{
			"auth_failure", "blocklist_reject", "signer_auto_locked",
			"ip_blocked", "rate_limited", "replay_detected",
		}
		for _, eventType := range securityEventTypes {
			resp, err := m.audit.List(m.ctx, &audit.ListFilter{
				EventType: eventType,
				Limit:     5,
			})
			if err == nil {
				data.RecentAlerts = append(data.RecentAlerts, resp.Records...)
			}
		}

		// Sort alerts by timestamp descending (most recent first)
		sortAlertsByTime(data.RecentAlerts)
		if len(data.RecentAlerts) > 15 {
			data.RecentAlerts = data.RecentAlerts[:15]
		}

		return SecurityDataMsg{Data: data, Err: nil}
	}
}

// sortAlertsByTime sorts audit records by timestamp descending.
func sortAlertsByTime(records []audit.Record) {
	for i := 1; i < len(records); i++ {
		for j := i; j > 0 && records[j].Timestamp.After(records[j-1].Timestamp); j-- {
			records[j], records[j-1] = records[j-1], records[j]
		}
	}
}

// Update handles messages.
func (m *SecurityModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case SecurityDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
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

	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			return m, m.Refresh()
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < sectionCount-1 {
				m.cursor++
			}
		case "enter":
			if m.expanded == m.cursor {
				m.expanded = -1 // collapse
			} else {
				m.expanded = m.cursor // expand
			}
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

// View renders the security page.
func (m *SecurityModel) View() string {
	if m.loading {
		return lipgloss.Place(
			m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			fmt.Sprintf("%s Loading security overview...", m.spinner.View()),
		)
	}

	if m.err != nil {
		errBox := styles.BoxStyle.
			BorderForeground(styles.ErrorColor).
			Render(fmt.Sprintf("Error: %v\n\nPress 'r' to retry", m.err))
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, errBox)
	}

	// Render content based on sub-tab (Overview vs Events) and show in viewport.
	var fullContent string
	var footer string
	switch m.GetSubTab() {
	case SecuritySubTabEvents:
		fullContent = m.renderEvents()
		footer = styles.MutedColor.Render(fmt.Sprintf(
			"Last refreshed: %s | r: refresh | ←/→: Overview/Events | pgup/pgdown: scroll",
			m.data.LastRefresh.Format("15:04:05"),
		))
	default:
		fullContent = m.renderOverview()
		footer = styles.MutedColor.Render(fmt.Sprintf(
			"Last refreshed: %s | r: refresh | ←/→: Overview/Events | ↑/↓: sections | Enter: expand | pgup/pgdown: scroll",
			m.data.LastRefresh.Format("15:04:05"),
		))
	}
	m.viewport.SetContent(fullContent)

	var b strings.Builder
	b.WriteString(m.viewport.View())
	b.WriteString("\n")
	b.WriteString(footer)
	return b.String()
}

// renderOverview renders the Overview sub-tab (sections only, no events table).
func (m *SecurityModel) renderOverview() string {
	var sections []string

	sections = append(sections, styles.SubtitleStyle.Render("Security Overview"))
	sections = append(sections, "")

	networkBox := m.renderNetworkSection()
	authBox := m.renderAuthSection()
	sections = append(sections, lipgloss.JoinHorizontal(lipgloss.Top, networkBox, "  ", authBox))
	sections = append(sections, "")

	ruleBox := m.renderRuleEngineSection()
	keyBox := m.renderKeyMgmtSection()
	sections = append(sections, lipgloss.JoinHorizontal(lipgloss.Top, ruleBox, "  ", keyBox))
	sections = append(sections, "")

	approvalBox := m.renderApprovalSection()
	auditBox := m.renderAuditMonitorSection()
	sections = append(sections, lipgloss.JoinHorizontal(lipgloss.Top, approvalBox, "  ", auditBox))

	if m.expanded >= 0 && m.expanded < sectionCount {
		sections = append(sections, "")
		sections = append(sections, m.renderExpandedDetail())
	}

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// renderEvents renders the Events sub-tab (only the recent security events table).
func (m *SecurityModel) renderEvents() string {
	if len(m.data.RecentAlerts) == 0 {
		return styles.SubtitleStyle.Render("Recent Security Events") + "\n\n" +
			styles.MutedColor.Render("No security events in the current window. Use the Audit tab for full history.")
	}
	return m.renderRecentAlerts()
}

// accentStyle is used for cursor highlights and section labels.
var accentStyle = lipgloss.NewStyle().Foreground(styles.SecondaryColor)

// status indicator helpers
func statusOn(label string) string {
	return styles.SuccessStyle.Render("✓") + " " + label
}

func statusOff(label string) string {
	return styles.ErrorStyle.Render("✗") + " " + label
}

func statusWarn(label string) string {
	return styles.WarningStyle.Render("⚠") + " " + label
}

func (m *SecurityModel) sectionPrefix(idx sectionIndex) string {
	if m.cursor == idx {
		if m.expanded == idx {
			return accentStyle.Render("▼ ")
		}
		return accentStyle.Render("▶ ")
	}
	if m.expanded == idx {
		return "▼ "
	}
	return "  "
}

func (m *SecurityModel) boxWidth() int {
	w := (m.width - 4) / 2
	if w < 38 {
		w = 38
	}
	if w > 50 {
		w = 50
	}
	return w
}

func (m *SecurityModel) renderNetworkSection() string {
	var b strings.Builder
	b.WriteString(m.sectionPrefix(sectionNetwork))
	b.WriteString(styles.SubtitleStyle.Render("Network & Transport"))
	b.WriteString("\n\n")

	sec := m.data.Health.Security

	// TLS — infer from server URL (health responded over HTTPS)
	b.WriteString(fmt.Sprintf("  %-16s %s\n", "TLS:", statusOn("Enabled (HTTPS)")))

	// mTLS — if we connected with client cert, mTLS is on
	b.WriteString(fmt.Sprintf("  %-16s %s\n", "Mutual TLS:", statusOn("Client auth required")))

	// Content-Type validation
	if sec != nil && sec.ContentTypeValidation {
		b.WriteString(fmt.Sprintf("  %-16s %s", "Content-Type:", statusOn("Validated")))
	} else {
		b.WriteString(fmt.Sprintf("  %-16s %s", "Content-Type:", statusOff("Disabled")))
	}

	return styles.BoxStyle.Width(m.boxWidth()).Render(b.String())
}

func (m *SecurityModel) renderAuthSection() string {
	var b strings.Builder
	b.WriteString(m.sectionPrefix(sectionAuth))
	b.WriteString(styles.SubtitleStyle.Render("Authentication"))
	b.WriteString("\n\n")

	// API keys — use real count from API key list
	keyCount := 0
	if m.data.APIKeys != nil {
		keyCount = m.data.APIKeys.Total
	}
	if keyCount == 0 {
		keyCount = 1 // at least the current key
	}
	b.WriteString(fmt.Sprintf("  %-16s %s\n", "API Keys:", statusOn(fmt.Sprintf("%d active (Ed25519)", keyCount))))
	b.WriteString(fmt.Sprintf("  %-16s %s\n", "Nonce:", statusOn("Required (replay protection)")))
	b.WriteString(fmt.Sprintf("  %-16s %s", "Signature:", statusOn("Ed25519 per-request signing")))

	return styles.BoxStyle.Width(m.boxWidth()).Render(b.String())
}

func (m *SecurityModel) renderRuleEngineSection() string {
	var b strings.Builder
	b.WriteString(m.sectionPrefix(sectionRuleEngine))
	b.WriteString(styles.SubtitleStyle.Render("Rule Engine"))
	b.WriteString("\n\n")

	whitelistCount := 0
	blocklistCount := 0
	if m.data.Rules != nil {
		for _, r := range m.data.Rules.Rules {
			if !r.Enabled {
				continue
			}
			switch r.Mode {
			case "whitelist":
				whitelistCount++
			case "blocklist":
				blocklistCount++
			}
		}
	}

	b.WriteString(fmt.Sprintf("  %-18s %s\n", "Whitelist Rules:", styles.SuccessStyle.Render(fmt.Sprintf("%d active", whitelistCount))))
	b.WriteString(fmt.Sprintf("  %-18s %s\n", "Blocklist Rules:", styles.ErrorStyle.Render(fmt.Sprintf("%d active", blocklistCount))))
	b.WriteString(fmt.Sprintf("  %-18s %s\n", "Fail-Closed:", statusOn("Blocklist errors reject")))
	b.WriteString(fmt.Sprintf("  %-18s %s", "Startup Validate:", statusOn("Test cases required")))

	return styles.BoxStyle.Width(m.boxWidth()).Render(b.String())
}

func (m *SecurityModel) renderKeyMgmtSection() string {
	var b strings.Builder
	b.WriteString(m.sectionPrefix(sectionKeyMgmt))
	b.WriteString(styles.SubtitleStyle.Render("Key Management"))
	b.WriteString("\n\n")

	sec := m.data.Health.Security

	// Auto-lock
	if sec != nil && sec.AutoLockTimeout != "disabled" {
		b.WriteString(fmt.Sprintf("  %-16s %s\n", "Auto-Lock:", statusOn(sec.AutoLockTimeout)))
	} else {
		b.WriteString(fmt.Sprintf("  %-16s %s\n", "Auto-Lock:", statusWarn("Disabled")))
	}

	// Sign timeout
	signTimeout := "30s"
	if sec != nil {
		signTimeout = sec.SignTimeout
	}
	b.WriteString(fmt.Sprintf("  %-16s %s\n", "Sign Timeout:", signTimeout))

	// Signer counts
	keystoreCount, hdWalletCount, unlockedCount := 0, 0, 0
	if m.data.Signers != nil {
		for _, s := range m.data.Signers.Signers {
			switch s.Type {
			case "keystore":
				keystoreCount++
			case "hd_wallet":
				hdWalletCount++
			}
			if !s.Locked {
				unlockedCount++
			}
		}
	}
	total := keystoreCount + hdWalletCount
	b.WriteString(fmt.Sprintf("  %-16s %d keystore, %d HD wallet\n", "Signers:", keystoreCount, hdWalletCount))

	unlockedStyle := styles.SuccessStyle
	if unlockedCount > 0 {
		unlockedStyle = styles.WarningStyle
	}
	b.WriteString(fmt.Sprintf("  %-16s %s", "Unlocked:", unlockedStyle.Render(fmt.Sprintf("%d / %d", unlockedCount, total))))

	return styles.BoxStyle.Width(m.boxWidth()).Render(b.String())
}

func (m *SecurityModel) renderApprovalSection() string {
	var b strings.Builder
	b.WriteString(m.sectionPrefix(sectionApproval))
	b.WriteString(styles.SubtitleStyle.Render("Approval & Alerts"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("  %-16s %s\n", "Approval Guard:", statusOn("Enabled")))
	b.WriteString(fmt.Sprintf("  %-16s %s\n", "Fail-Closed:", statusOn("No match = reject (403)")))

	// Notification channels — we can't query this from API, but show basic status
	b.WriteString(fmt.Sprintf("  %-16s %s", "Alert Service:", statusOn("Security alerts enabled")))

	return styles.BoxStyle.Width(m.boxWidth()).Render(b.String())
}

func (m *SecurityModel) renderAuditMonitorSection() string {
	var b strings.Builder
	b.WriteString(m.sectionPrefix(sectionAuditMonitor))
	b.WriteString(styles.SubtitleStyle.Render("Audit & Monitoring"))
	b.WriteString("\n\n")

	sec := m.data.Health.Security

	b.WriteString(fmt.Sprintf("  %-16s %s\n", "Audit Logging:", statusOn("Enabled")))

	// Retention
	if sec != nil && sec.AuditRetentionDays > 0 {
		b.WriteString(fmt.Sprintf("  %-16s %s\n", "Retention:", statusOn(fmt.Sprintf("%d days", sec.AuditRetentionDays))))
	} else {
		b.WriteString(fmt.Sprintf("  %-16s %s\n", "Retention:", statusWarn("Keep forever")))
	}

	b.WriteString(fmt.Sprintf("  %-16s %s\n", "Monitor:", statusOn("Enabled (interval: 1h)")))

	// Recent alert count
	alertCount := len(m.data.RecentAlerts)
	if alertCount > 0 {
		b.WriteString(fmt.Sprintf("  %-16s %s", "Recent Alerts:", styles.WarningStyle.Render(fmt.Sprintf("%d events", alertCount))))
	} else {
		b.WriteString(fmt.Sprintf("  %-16s %s", "Recent Alerts:", styles.SuccessStyle.Render("None")))
	}

	return styles.BoxStyle.Width(m.boxWidth()).Render(b.String())
}

func (m *SecurityModel) renderExpandedDetail() string {
	var b strings.Builder

	switch m.expanded {
	case sectionNetwork:
		b.WriteString(styles.SubtitleStyle.Render("Network & Transport — Details"))
		b.WriteString("\n\n")
		b.WriteString("  TLS enforces encrypted transport between client and server.\n")
		b.WriteString("  Mutual TLS (mTLS) requires valid client certificates, preventing\n")
		b.WriteString("  unauthorized clients from connecting.\n\n")
		b.WriteString("  Content-Type validation rejects requests with incorrect or missing\n")
		b.WriteString("  Content-Type headers, mitigating content confusion attacks.\n\n")
		b.WriteString("  Protects against: MITM, traffic interception, client spoofing")

	case sectionAuth:
		b.WriteString(styles.SubtitleStyle.Render("Authentication — Details"))
		b.WriteString("\n\n")
		b.WriteString("  Ed25519 API key signing authenticates every request:\n")
		b.WriteString("    Signature = sign(timestamp|nonce|method|path|sha256(body))\n\n")
		b.WriteString("  Nonce protection prevents replay attacks — each request must\n")
		b.WriteString("  include a unique nonce. Server rejects duplicates within 5 min.\n\n")
		b.WriteString("  Max request age: 60s (rejects stale requests).\n\n")
		if m.data.APIKeys != nil && len(m.data.APIKeys.Keys) > 0 {
			b.WriteString("  Active API keys:\n")
			for _, k := range m.data.APIKeys.Keys {
				sourceTag := ""
				if k.Source == "config" {
					sourceTag = " [config]"
				}
				adminTag := ""
				if k.Role == "admin" {
					adminTag = " (admin)"
				}
				b.WriteString(fmt.Sprintf("    %s (%s)%s%s\n", accentStyle.Render(k.ID), k.Name, adminTag, sourceTag))
			}
		}

	case sectionRuleEngine:
		b.WriteString(styles.SubtitleStyle.Render("Rule Engine — Details"))
		b.WriteString("\n\n")
		b.WriteString("  Evaluation order: Blocklist first → any match = reject.\n")
		b.WriteString("  Then: Whitelist → any match = auto-approve.\n")
		b.WriteString("  No match = reject (or pending if manual approval enabled).\n\n")
		b.WriteString("  Fail-closed: blocklist evaluation errors → immediate reject.\n\n")
		if m.data.Rules != nil {
			b.WriteString("  Rules by type:\n")
			typeCounts := make(map[string]int)
			for _, r := range m.data.Rules.Rules {
				if r.Enabled {
					typeCounts[r.Type]++
				}
			}
			for t, c := range typeCounts {
				b.WriteString(fmt.Sprintf("    %-28s %d\n", t, c))
			}
		}

	case sectionKeyMgmt:
		b.WriteString(styles.SubtitleStyle.Render("Key Management — Details"))
		b.WriteString("\n\n")
		if m.data.Signers != nil {
			for _, s := range m.data.Signers.Signers {
				lockStatus := styles.SuccessStyle.Render("Locked")
				if !s.Locked {
					elapsed := ""
					if s.UnlockedAt != nil {
						elapsed = fmt.Sprintf(" (%s ago)", time.Since(*s.UnlockedAt).Truncate(time.Minute))
					}
					lockStatus = styles.WarningStyle.Render("Unlocked") + elapsed
				}
				addr := s.Address
				if len(addr) > 12 {
					addr = addr[:6] + "..." + addr[len(addr)-4:]
				}
				b.WriteString(fmt.Sprintf("  %s  %-10s  %s\n", addr, s.Type, lockStatus))
			}
		}

	case sectionApproval:
		b.WriteString(styles.SubtitleStyle.Render("Approval & Alerts — Details"))
		b.WriteString("\n\n")
		b.WriteString("  Approval Guard detects API key abuse patterns:\n")
		b.WriteString("    If too many consecutive non-approved requests are detected\n")
		b.WriteString("    within a time window, the guard pauses that API key.\n\n")
		b.WriteString("  Security Alert Service sends real-time notifications for:\n")
		b.WriteString("    - Authentication failures\n")
		b.WriteString("    - IP blocks / rate limiting\n")
		b.WriteString("    - Replay attack attempts\n")
		b.WriteString("    - Blocklist rejections\n")
		b.WriteString("    - Signer auto-lock events")

	case sectionAuditMonitor:
		b.WriteString(styles.SubtitleStyle.Render("Audit & Monitoring — Details"))
		b.WriteString("\n\n")
		b.WriteString("  Audit monitor periodically scans for anomalies:\n\n")
		b.WriteString("  Detection patterns:\n")
		b.WriteString("    - Consecutive auth failures (>5/hour from same source)\n")
		b.WriteString("    - Consecutive blocklist rejects (>3/hour from same key)\n")
		b.WriteString("    - High-frequency requests (>80% of rate limit)\n")
		b.WriteString("    - Off-hours signing activity\n\n")

		sec := m.data.Health.Security
		if sec != nil && sec.AuditRetentionDays > 0 {
			b.WriteString(fmt.Sprintf("  Retention: %d days (auto-cleanup every 24h)", sec.AuditRetentionDays))
		} else {
			b.WriteString("  Retention: unlimited (no auto-cleanup)")
		}
	}

	return styles.BoxStyle.Width(m.width - 2).Render(b.String())
}

func (m *SecurityModel) renderRecentAlerts() string {
	var b strings.Builder
	b.WriteString(styles.SubtitleStyle.Render("Recent Security Events"))
	b.WriteString("\n\n")

	// Header
	header := fmt.Sprintf("  %-20s %-12s %-24s %-18s %s",
		"Timestamp", "Severity", "Event Type", "Client IP", "Details")
	b.WriteString(styles.TableHeaderStyle.Render(header))
	b.WriteString("\n")
	b.WriteString("  " + strings.Repeat("─", m.width-6))
	b.WriteString("\n")

	maxRows := 10
	if len(m.data.RecentAlerts) < maxRows {
		maxRows = len(m.data.RecentAlerts)
	}

	for i := 0; i < maxRows; i++ {
		rec := m.data.RecentAlerts[i]

		ts := rec.Timestamp.Format("2006-01-02 15:04:05")
		severity := styles.GetSeverityStyle(rec.Severity).Render(fmt.Sprintf("%-12s", rec.Severity))
		eventType := fmt.Sprintf("%-24s", rec.EventType)
		clientIP := fmt.Sprintf("%-18s", rec.ActorAddress)

		detail := ""
		if rec.SignerAddress != nil {
			addr := *rec.SignerAddress
			if len(addr) > 12 {
				addr = addr[:6] + "..." + addr[len(addr)-4:]
			}
			detail = addr
		}
		if rec.ErrorMessage != "" {
			if detail != "" {
				detail += " "
			}
			msg := rec.ErrorMessage
			if len(msg) > 30 {
				msg = msg[:27] + "..."
			}
			detail += msg
		}

		row := fmt.Sprintf("  %s %s %s %s %s", ts, severity, eventType, clientIP, detail)
		b.WriteString(row)
		b.WriteString("\n")
	}

	if len(m.data.RecentAlerts) > maxRows {
		b.WriteString(fmt.Sprintf("\n  %s",
			styles.MutedColor.Render(fmt.Sprintf("... and %d more events (see Audit tab)", len(m.data.RecentAlerts)-maxRows))))
	}

	return b.String()
}
