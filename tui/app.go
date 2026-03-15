package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/tui/styles"
	"github.com/ivanzzeth/remote-signer/tui/views"
)

// ViewType represents the current view
type ViewType int

const (
	ViewDashboard ViewType = iota
	ViewRequests
	ViewRequestDetail
	ViewRules
	ViewRuleDetail
	ViewAudit
	ViewSigners
	ViewSignerDetail
	ViewMetrics
	ViewHDWallets
	ViewHDWalletDetail
	ViewSecurity
	ViewAPIKeys
	ViewIPWhitelist
	ViewTemplates
	ViewPresets
	ViewPresetDetail
)

// keyMap defines the key bindings for the application
type keyMap struct {
	Tab       key.Binding
	ShiftTab  key.Binding
	Enter     key.Binding
	Back      key.Binding
	Refresh   key.Binding
	Approve   key.Binding
	Reject    key.Binding
	Filter    key.Binding
	Help      key.Binding
	Quit      key.Binding
	Up        key.Binding
	Down      key.Binding
	Left      key.Binding
	Right     key.Binding
	PageUp    key.Binding
	PageDown  key.Binding
	Home      key.Binding
	End       key.Binding
	Delete    key.Binding
	Toggle    key.Binding
	Generate  key.Binding
	Number1   key.Binding
	Number2   key.Binding
	Number3   key.Binding
	Number4   key.Binding
	Number5   key.Binding
	Number6   key.Binding
	Number7   key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Enter, k.Back, k.Refresh, k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Tab, k.ShiftTab, k.Enter, k.Back},
		{k.Up, k.Down, k.Left, k.Right, k.PageUp, k.PageDown},
		{k.Approve, k.Reject, k.Generate},
		{k.Filter, k.Refresh, k.Delete, k.Toggle},
		{k.Number1, k.Number2, k.Number3, k.Number4, k.Number5, k.Number6, k.Number7},
		{k.Help, k.Quit},
	}
}

var keys = keyMap{
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next tab"),
	),
	ShiftTab: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift+tab", "prev tab"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select/confirm"),
	),
	Back: key.NewBinding(
		key.WithKeys("esc", "backspace"),
		key.WithHelp("esc/backspace", "back"),
	),
	Refresh: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "refresh"),
	),
	Approve: key.NewBinding(
		key.WithKeys("a"),
		key.WithHelp("a", "approve"),
	),
	Reject: key.NewBinding(
		key.WithKeys("x"),
		key.WithHelp("x", "reject"),
	),
	Filter: key.NewBinding(
		key.WithKeys("f"),
		key.WithHelp("f", "filter"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "down"),
	),
	Left: key.NewBinding(
		key.WithKeys("left", "h"),
		key.WithHelp("←/h", "prev sub-tab"),
	),
	Right: key.NewBinding(
		key.WithKeys("right", "l"),
		key.WithHelp("→/l", "next sub-tab"),
	),
	PageUp: key.NewBinding(
		key.WithKeys("pgup", "ctrl+u"),
		key.WithHelp("pgup", "page up"),
	),
	PageDown: key.NewBinding(
		key.WithKeys("pgdown", "ctrl+d"),
		key.WithHelp("pgdown", "page down"),
	),
	Home: key.NewBinding(
		key.WithKeys("home", "g"),
		key.WithHelp("home/g", "go to start"),
	),
	End: key.NewBinding(
		key.WithKeys("end", "G"),
		key.WithHelp("end/G", "go to end"),
	),
	Delete: key.NewBinding(
		key.WithKeys("d"),
		key.WithHelp("d", "delete"),
	),
	Toggle: key.NewBinding(
		key.WithKeys("t"),
		key.WithHelp("t", "toggle enabled"),
	),
	Generate: key.NewBinding(
		key.WithKeys("g"),
		key.WithHelp("g", "generate rule"),
	),
	Number1: key.NewBinding(
		key.WithKeys("1"),
		key.WithHelp("1", "dashboard"),
	),
	Number2: key.NewBinding(
		key.WithKeys("2"),
		key.WithHelp("2", "requests"),
	),
	Number3: key.NewBinding(
		key.WithKeys("3"),
		key.WithHelp("3", "ACLs"),
	),
	Number4: key.NewBinding(
		key.WithKeys("4"),
		key.WithHelp("4", "audit"),
	),
	Number5: key.NewBinding(
		key.WithKeys("5"),
		key.WithHelp("5", "signers"),
	),
	Number6: key.NewBinding(
		key.WithKeys("6"),
		key.WithHelp("6", "metrics"),
	),
	Number7: key.NewBinding(
		key.WithKeys("7"),
		key.WithHelp("7", "security"),
	),
}

// Model represents the main application state
type Model struct {
	client       *client.Client
	ctx          context.Context
	width        int
	height       int
	activeTab    int
	rulesSubTab  int // 0=Rules, 1=Templates, 2=Presets, 3=API Keys, 4=IP Whitelist; only when activeTab==2 (ACLs)
	signersSubTab int // 0=List, 1=HD Wallets; only when activeTab==4 (Signers)
	currentView  ViewType
	previousView ViewType
	help         help.Model
	showHelp     bool
	err          error
	statusMsg    string

	// Views
	dashboard      *views.DashboardModel
	requests       *views.RequestsModel
	requestDetail  *views.RequestDetailModel
	rules          *views.RulesModel
	ruleDetail     *views.RuleDetailModel
	audit          *views.AuditModel
	signers        *views.SignersModel
	signerDetail   *views.SignerDetailModel
	metrics        *views.MetricsModel
	hdwallets      *views.HDWalletsModel
	hdwalletDetail *views.HDWalletDetailModel
	security         *views.SecurityModel
	apikeysView      *views.APIKeysModel
	ipWhitelistView  *views.IPWhitelistModel
	templates        *views.TemplatesModel
	presets        *views.PresetsModel
	presetDetail   *views.PresetDetailModel
}

// NewModel creates a new application model
func NewModel(c *client.Client) (*Model, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}

	ctx := context.Background()
	h := help.New()
	h.ShowAll = false

	dashboard, err := views.NewDashboardModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create dashboard view: %w", err)
	}

	requests, err := views.NewRequestsModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create requests view: %w", err)
	}

	requestDetail, err := views.NewRequestDetailModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create request detail view: %w", err)
	}

	rules, err := views.NewRulesModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create rules view: %w", err)
	}

	ruleDetail, err := views.NewRuleDetailModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule detail view: %w", err)
	}

	audit, err := views.NewAuditModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit view: %w", err)
	}

	signers, err := views.NewSignersModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create signers view: %w", err)
	}

	signerDetail, err := views.NewSignerDetailModel(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer detail view: %w", err)
	}

	metrics, err := views.NewMetricsModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics view: %w", err)
	}

	hdwallets, err := views.NewHDWalletsModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create hdwallets view: %w", err)
	}

	hdwalletDetail, err := views.NewHDWalletDetailModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create hdwallet detail view: %w", err)
	}

	security, err := views.NewSecurityModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create security view: %w", err)
	}

	apikeysView, err := views.NewAPIKeysModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create api keys view: %w", err)
	}

	ipWhitelistView, err := views.NewIPWhitelistModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IP whitelist view: %w", err)
	}

	templates, err := views.NewTemplatesModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create templates view: %w", err)
	}

	presets, err := views.NewPresetsModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create presets view: %w", err)
	}

	presetDetail, err := views.NewPresetDetailModel(c, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create preset detail view: %w", err)
	}

	return &Model{
		client:        c,
		ctx:           ctx,
		activeTab:     0,
		signersSubTab: 0,
		currentView:   ViewDashboard,
		help:           h,
		dashboard:      dashboard,
		requests:       requests,
		requestDetail:  requestDetail,
		rules:          rules,
		ruleDetail:     ruleDetail,
		audit:          audit,
		signers:        signers,
		signerDetail:   signerDetail,
		metrics:        metrics,
		hdwallets:      hdwallets,
		hdwalletDetail: hdwalletDetail,
		security:       security,
		apikeysView:    apikeysView,
		ipWhitelistView: ipWhitelistView,
		templates:      templates,
		presets:        presets,
		presetDetail:   presetDetail,
	}, nil
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.dashboard.Init(),
		m.requests.Init(),
		m.rules.Init(),
		m.audit.Init(),
		m.signers.Init(),
		m.metrics.Init(),
		m.hdwallets.Init(),
		m.security.Init(),
		m.apikeysView.Init(),
		m.templates.Init(),
		m.presets.Init(),
	)
}

// Update handles messages and updates the model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width

		// Update all views with new size
		m.dashboard.SetSize(msg.Width, msg.Height-6)
		m.requests.SetSize(msg.Width, msg.Height-6)
		m.requestDetail.SetSize(msg.Width, msg.Height-6)
		m.rules.SetSize(msg.Width, msg.Height-6)
		m.ruleDetail.SetSize(msg.Width, msg.Height-6)
		m.audit.SetSize(msg.Width, msg.Height-6)
		m.signers.SetSize(msg.Width, msg.Height-6)
		m.signerDetail.SetSize(msg.Width, msg.Height-6)
		m.metrics.SetSize(msg.Width, msg.Height-6)
		m.hdwallets.SetSize(msg.Width, msg.Height-6)
		m.hdwalletDetail.SetSize(msg.Width, msg.Height-6)
		m.security.SetSize(msg.Width, msg.Height-6)
		m.apikeysView.SetSize(msg.Width, msg.Height-6)
		m.ipWhitelistView.SetSize(msg.Width, msg.Height-6)
		m.templates.SetSize(msg.Width, msg.Height-6)
		m.presets.SetSize(msg.Width, msg.Height-6)
		m.presetDetail.SetSize(msg.Width, msg.Height-6)
		return m, nil

	case tea.KeyMsg:
		// ctrl+c always quits regardless of input state
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		// Skip global key handling when the current view is capturing input
		// (e.g., form fields, text inputs, filters). Route directly to the view instead.
		if !m.isCurrentViewCapturingInput() {
			// Global key handling
			switch {
			case key.Matches(msg, keys.Quit):
				if m.isTopLevelView() {
					return m, tea.Quit
				}
				// If in detail view, go back instead of quitting
				m.currentView = m.previousView
				return m, nil

			case key.Matches(msg, keys.Help):
				m.showHelp = !m.showHelp
				return m, nil

			case key.Matches(msg, keys.Number1):
				m.activeTab = 0
				m.currentView = ViewDashboard
				return m, m.dashboard.Refresh()

			case key.Matches(msg, keys.Number2):
				m.activeTab = 1
				m.currentView = ViewRequests
				return m, m.requests.Refresh()

			case key.Matches(msg, keys.Number3):
				m.activeTab = 2
				m.rulesSubTab = 0
				m.currentView = ViewRules
				return m, m.rules.Refresh()

			case key.Matches(msg, keys.Number4):
				m.activeTab = 3
				m.currentView = ViewAudit
				return m, m.audit.Refresh()

			case key.Matches(msg, keys.Number5):
				m.activeTab = 4
				m.signersSubTab = 0
				m.currentView = ViewSigners
				return m, m.signers.Refresh()

			case key.Matches(msg, keys.Number6):
				m.activeTab = 5
				m.currentView = ViewMetrics
				return m, m.metrics.Refresh()

			case key.Matches(msg, keys.Number7):
				m.activeTab = 6
				m.currentView = ViewSecurity
				return m, m.security.Refresh()

			case key.Matches(msg, keys.Tab):
				// Only switch top-level tabs (7 tabs)
				if m.isTopLevelView() {
					m.activeTab = (m.activeTab + 1) % 7
					m.currentView = m.tabToView(m.activeTab)
					if m.activeTab == 2 {
						m.rulesSubTab = 0
					}
					if m.activeTab == 4 {
						m.signersSubTab = 0
					}
					return m, m.refreshCurrentView()
				}

			case key.Matches(msg, keys.ShiftTab):
				if m.isTopLevelView() {
					m.activeTab = (m.activeTab + 6) % 7
					m.currentView = m.tabToView(m.activeTab)
					if m.activeTab == 2 {
						m.rulesSubTab = 0
					}
					if m.activeTab == 4 {
						m.signersSubTab = 0
					}
					return m, m.refreshCurrentView()
				}

			case key.Matches(msg, keys.Left):
				if m.currentView == ViewRules || m.currentView == ViewTemplates || m.currentView == ViewPresets || m.currentView == ViewAPIKeys || m.currentView == ViewIPWhitelist {
					m.rulesSubTab = (m.rulesSubTab + 4) % 5 // prev sub-tab (0->4, 1->0, ..., 4->3)
					m.currentView = m.rulesSubTabToView(m.rulesSubTab)
					return m, m.refreshCurrentView()
				}
				if m.currentView == ViewSigners || m.currentView == ViewHDWallets {
					m.signersSubTab = (m.signersSubTab + 1) % 2 // List <-> HD Wallets
					m.currentView = m.signersSubTabToView(m.signersSubTab)
					return m, m.refreshCurrentView()
				}
				if m.currentView == ViewSecurity {
					m.security.SetSubTab((m.security.GetSubTab() + 1) % 2) // Overview <-> Events
					return m, nil
				}

			case key.Matches(msg, keys.Right):
				if m.currentView == ViewRules || m.currentView == ViewTemplates || m.currentView == ViewPresets || m.currentView == ViewAPIKeys || m.currentView == ViewIPWhitelist {
					m.rulesSubTab = (m.rulesSubTab + 1) % 5 // next sub-tab (0->1, ..., 4->0)
					m.currentView = m.rulesSubTabToView(m.rulesSubTab)
					return m, m.refreshCurrentView()
				}
				if m.currentView == ViewSigners || m.currentView == ViewHDWallets {
					m.signersSubTab = (m.signersSubTab + 1) % 2 // List <-> HD Wallets
					m.currentView = m.signersSubTabToView(m.signersSubTab)
					return m, m.refreshCurrentView()
				}
				if m.currentView == ViewSecurity {
					m.security.SetSubTab((m.security.GetSubTab() + 1) % 2) // Overview <-> Events
					return m, nil
				}

			case key.Matches(msg, keys.Back):
				if m.currentView == ViewRequestDetail || m.currentView == ViewRuleDetail || m.currentView == ViewSignerDetail || m.currentView == ViewHDWalletDetail || m.currentView == ViewPresetDetail {
					m.currentView = m.previousView
					return m, m.refreshCurrentView()
				}
			}
		}
	}

	// Route to current view for handling
	switch m.currentView {
	case ViewDashboard:
		newDashboard, cmd := m.dashboard.Update(msg)
		m.dashboard = newDashboard.(*views.DashboardModel)
		cmds = append(cmds, cmd)

	case ViewRequests:
		newRequests, cmd := m.requests.Update(msg)
		m.requests = newRequests.(*views.RequestsModel)
		cmds = append(cmds, cmd)

		// Check if user selected a request
		if selected := m.requests.GetSelectedRequestID(); selected != "" {
			if keyMsg, ok := msg.(tea.KeyMsg); ok && key.Matches(keyMsg, keys.Enter) {
				m.previousView = m.currentView
				m.currentView = ViewRequestDetail
				cmds = append(cmds, m.requestDetail.LoadRequest(selected))
			}
		}

	case ViewRequestDetail:
		newDetail, cmd := m.requestDetail.Update(msg)
		m.requestDetail = newDetail.(*views.RequestDetailModel)
		cmds = append(cmds, cmd)

		// Check if action was completed and we should go back
		if m.requestDetail.ShouldGoBack() {
			m.currentView = ViewRequests
			m.requestDetail.ResetGoBack()
			cmds = append(cmds, m.requests.Refresh())
		}

	case ViewRules:
		newRules, cmd := m.rules.Update(msg)
		m.rules = newRules.(*views.RulesModel)
		cmds = append(cmds, cmd)

		// Check if user selected a rule
		if selected := m.rules.GetSelectedRuleID(); selected != "" {
			if keyMsg, ok := msg.(tea.KeyMsg); ok && key.Matches(keyMsg, keys.Enter) {
				m.previousView = m.currentView
				m.currentView = ViewRuleDetail
				cmds = append(cmds, m.ruleDetail.LoadRule(selected))
			}
		}

	case ViewRuleDetail:
		newDetail, cmd := m.ruleDetail.Update(msg)
		m.ruleDetail = newDetail.(*views.RuleDetailModel)
		cmds = append(cmds, cmd)

		// Check if action was completed and we should go back
		if m.ruleDetail.ShouldGoBack() {
			m.currentView = ViewRules
			m.ruleDetail.ResetGoBack()
			cmds = append(cmds, m.rules.Refresh())
		}

	case ViewAudit:
		newAudit, cmd := m.audit.Update(msg)
		m.audit = newAudit.(*views.AuditModel)
		cmds = append(cmds, cmd)

	case ViewSigners:
		newSigners, cmd := m.signers.Update(msg)
		m.signers = newSigners.(*views.SignersModel)
		cmds = append(cmds, cmd)

		// Check if user pressed Enter on a selected signer
		if selected := m.signers.GetSelectedSigner(); selected != nil {
			if keyMsg, ok := msg.(tea.KeyMsg); ok && key.Matches(keyMsg, keys.Enter) && !m.signers.IsCapturingInput() {
				m.previousView = m.currentView
				m.currentView = ViewSignerDetail
				m.signerDetail.LoadSigner(*selected)
			}
		}

	case ViewSignerDetail:
		newDetail, cmd := m.signerDetail.Update(msg)
		m.signerDetail = newDetail.(*views.SignerDetailModel)
		cmds = append(cmds, cmd)

		if m.signerDetail.ShouldGoBack() {
			m.currentView = ViewSigners
			m.signerDetail.ResetGoBack()
			cmds = append(cmds, m.signers.Refresh())
		}

	case ViewMetrics:
		newMetrics, cmd := m.metrics.Update(msg)
		m.metrics = newMetrics.(*views.MetricsModel)
		cmds = append(cmds, cmd)

	case ViewHDWallets:
		newHDWallets, cmd := m.hdwallets.Update(msg)
		m.hdwallets = newHDWallets.(*views.HDWalletsModel)
		cmds = append(cmds, cmd)

		// Check if user selected a wallet for detail view
		if m.hdwallets.ShouldOpenDetail() {
			addr := m.hdwallets.GetSelectedPrimaryAddr()
			m.hdwallets.ResetOpenDetail()
			m.previousView = m.currentView
			m.currentView = ViewHDWalletDetail
			cmds = append(cmds, m.hdwalletDetail.LoadWallet(addr))
		}

	case ViewHDWalletDetail:
		newDetail, cmd := m.hdwalletDetail.Update(msg)
		m.hdwalletDetail = newDetail.(*views.HDWalletDetailModel)
		cmds = append(cmds, cmd)

		if m.hdwalletDetail.ShouldGoBack() {
			m.currentView = ViewHDWallets
			m.hdwalletDetail.ResetGoBack()
			cmds = append(cmds, m.hdwallets.Refresh())
		}

	case ViewSecurity:
		newSecurity, cmd := m.security.Update(msg)
		m.security = newSecurity.(*views.SecurityModel)
		cmds = append(cmds, cmd)

	case ViewAPIKeys:
		newAPIKeys, cmd := m.apikeysView.Update(msg)
		m.apikeysView = newAPIKeys.(*views.APIKeysModel)
		cmds = append(cmds, cmd)

	case ViewIPWhitelist:
		newIPW, cmd := m.ipWhitelistView.Update(msg)
		m.ipWhitelistView = newIPW.(*views.IPWhitelistModel)
		cmds = append(cmds, cmd)

	case ViewTemplates:
		newTemplates, cmd := m.templates.Update(msg)
		m.templates = newTemplates.(*views.TemplatesModel)
		cmds = append(cmds, cmd)

	case ViewPresets:
		newPresets, cmd := m.presets.Update(msg)
		m.presets = newPresets.(*views.PresetsModel)
		cmds = append(cmds, cmd)

		if m.presets.ShouldOpenDetail() {
			m.presets.ResetOpenDetail()
			id := m.presets.GetSelectedPresetID()
			if id != "" {
				m.previousView = m.currentView
				m.currentView = ViewPresetDetail
				cmds = append(cmds, m.presetDetail.LoadPreset(id))
			}
		}

	case ViewPresetDetail:
		newDetail, cmd := m.presetDetail.Update(msg)
		m.presetDetail = newDetail.(*views.PresetDetailModel)
		cmds = append(cmds, cmd)

		if m.presetDetail.ShouldGoBack() {
			m.currentView = ViewPresets
			m.presetDetail.ResetGoBack()
			cmds = append(cmds, m.presets.Refresh())
		}
	}

	return m, tea.Batch(cmds...)
}

// View renders the application
func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	var s strings.Builder

	// Header with tabs
	s.WriteString(m.renderHeader())
	s.WriteString("\n")

	// Content
	contentHeight := m.height - 6
	if m.showHelp {
		contentHeight -= 4
	}

	content := m.renderContent(contentHeight)
	s.WriteString(content)

	// Help
	if m.showHelp {
		s.WriteString("\n")
		s.WriteString(m.help.View(keys))
	} else {
		s.WriteString("\n")
		s.WriteString(styles.HelpStyle.Render("Press ? for help"))
	}

	return s.String()
}

func (m Model) renderHeader() string {
	tabs := []string{"Dashboard", "Requests", "ACLs", "Audit", "Signers", "Metrics", "Security"}
	var renderedTabs []string

	for i, tab := range tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, styles.ActiveTabStyle.Render(fmt.Sprintf("[%d] %s", i+1, tab)))
		} else {
			renderedTabs = append(renderedTabs, styles.TabStyle.Render(fmt.Sprintf("[%d] %s", i+1, tab)))
		}
	}

	title := styles.TitleStyle.Render("Remote Signer TUI")
	tabLine := lipgloss.JoinHorizontal(lipgloss.Center, renderedTabs...)

	out := lipgloss.JoinVertical(lipgloss.Left, title, tabLine)

	// ACLs sub-tabs when ACLs is the active top-level tab (Rules, Templates, Presets, API Keys, IP Whitelist)
	if m.activeTab == 2 {
		subNames := []string{"Rules", "Templates", "Presets", "API Keys", "IP Whitelist"}
		var subRendered []string
		for i, name := range subNames {
			if i == m.rulesSubTab {
				subRendered = append(subRendered, styles.ActiveTabStyle.Render(name))
			} else {
				subRendered = append(subRendered, styles.TabStyle.Render(name))
			}
		}
		subLine := lipgloss.JoinHorizontal(lipgloss.Left, subRendered...)
		out = lipgloss.JoinVertical(lipgloss.Left, out, subLine)
	}

	// Signers sub-tabs when Signers is the active top-level tab (List | HD Wallets)
	if m.activeTab == 4 {
		subNames := []string{"List", "HD Wallets"}
		var subRendered []string
		for i, name := range subNames {
			if i == m.signersSubTab {
				subRendered = append(subRendered, styles.ActiveTabStyle.Render(name))
			} else {
				subRendered = append(subRendered, styles.TabStyle.Render(name))
			}
		}
		subLine := lipgloss.JoinHorizontal(lipgloss.Left, subRendered...)
		out = lipgloss.JoinVertical(lipgloss.Left, out, subLine)
	}

	// Security sub-tabs when Security is the active top-level tab
	if m.activeTab == 6 {
		subNames := []string{"Overview", "Events"}
		subTab := m.security.GetSubTab()
		var subRendered []string
		for i, name := range subNames {
			if i == subTab {
				subRendered = append(subRendered, styles.ActiveTabStyle.Render(name))
			} else {
				subRendered = append(subRendered, styles.TabStyle.Render(name))
			}
		}
		subLine := lipgloss.JoinHorizontal(lipgloss.Left, subRendered...)
		out = lipgloss.JoinVertical(lipgloss.Left, out, subLine)
	}

	return out
}

func (m Model) renderContent(_ int) string {
	switch m.currentView {
	case ViewDashboard:
		return m.dashboard.View()
	case ViewRequests:
		return m.requests.View()
	case ViewRequestDetail:
		return m.requestDetail.View()
	case ViewRules:
		return m.rules.View()
	case ViewRuleDetail:
		return m.ruleDetail.View()
	case ViewAudit:
		return m.audit.View()
	case ViewSigners:
		return m.signers.View()
	case ViewSignerDetail:
		return m.signerDetail.View()
	case ViewMetrics:
		return m.metrics.View()
	case ViewHDWallets:
		return m.hdwallets.View()
	case ViewHDWalletDetail:
		return m.hdwalletDetail.View()
	case ViewSecurity:
		return m.security.View()
	case ViewAPIKeys:
		return m.apikeysView.View()
	case ViewIPWhitelist:
		return m.ipWhitelistView.View()
	case ViewTemplates:
		return m.templates.View()
	case ViewPresets:
		return m.presets.View()
	case ViewPresetDetail:
		return m.presetDetail.View()
	default:
		return "Unknown view"
	}
}

func (m Model) refreshCurrentView() tea.Cmd {
	switch m.currentView {
	case ViewDashboard:
		return m.dashboard.Refresh()
	case ViewRequests:
		return m.requests.Refresh()
	case ViewRules:
		return m.rules.Refresh()
	case ViewAudit:
		return m.audit.Refresh()
	case ViewSigners:
		return m.signers.Refresh()
	case ViewMetrics:
		return m.metrics.Refresh()
	case ViewHDWallets:
		return m.hdwallets.Refresh()
	case ViewSecurity:
		return m.security.Refresh()
	case ViewAPIKeys:
		return m.apikeysView.Refresh()
	case ViewIPWhitelist:
		return m.ipWhitelistView.Refresh()
	case ViewTemplates:
		return m.templates.Refresh()
	case ViewPresets:
		return m.presets.Refresh()
	default:
		return nil
	}
}

// isCurrentViewCapturingInput returns true if the current view is in an input-capturing state
// (e.g., text input, form, filter). When true, global key bindings should be suppressed.
func (m Model) isCurrentViewCapturingInput() bool {
	switch m.currentView {
	case ViewRequests:
		return m.requests.IsCapturingInput()
	case ViewRules:
		return m.rules.IsCapturingInput()
	case ViewAudit:
		return m.audit.IsCapturingInput()
	case ViewSigners:
		return m.signers.IsCapturingInput()
	case ViewSignerDetail:
		return m.signerDetail.IsCapturingInput()
	case ViewHDWallets:
		return m.hdwallets.IsCapturingInput()
	case ViewHDWalletDetail:
		return m.hdwalletDetail.IsCapturingInput()
	case ViewSecurity:
		return m.security.IsCapturingInput()
	case ViewAPIKeys:
		return m.apikeysView.IsCapturingInput()
	case ViewIPWhitelist:
		return m.ipWhitelistView.IsCapturingInput()
	case ViewTemplates:
		return m.templates.IsCapturingInput()
	case ViewPresets:
		return m.presets.IsCapturingInput()
	case ViewPresetDetail:
		return m.presetDetail.IsCapturingInput()
	default:
		return false
	}
}

// tabToView converts top-level tab index (0-6) to ViewType. Tab 2 is ACLs, tab 4 is Signers (sub-tabs List/HD Wallets).
func (m Model) tabToView(tab int) ViewType {
	switch tab {
	case 0:
		return ViewDashboard
	case 1:
		return ViewRequests
	case 2:
		return m.rulesSubTabToView(m.rulesSubTab)
	case 3:
		return ViewAudit
	case 4:
		return m.signersSubTabToView(m.signersSubTab)
	case 5:
		return ViewMetrics
	case 6:
		return ViewSecurity
	default:
		return ViewDashboard
	}
}

// signersSubTabToView returns the ViewType for the given Signers sub-tab (0=List, 1=HD Wallets).
func (m Model) signersSubTabToView(sub int) ViewType {
	switch sub {
	case 1:
		return ViewHDWallets
	default:
		return ViewSigners
	}
}

// isTopLevelView returns true when the current view is one of the seven top-level tab views
// (including ACLs sub-views and Signers sub-views: List, HD Wallets).
func (m Model) isTopLevelView() bool {
	switch m.currentView {
	case ViewDashboard, ViewRequests, ViewRules, ViewAudit, ViewSigners, ViewMetrics,
		ViewHDWallets, ViewSecurity, ViewAPIKeys, ViewIPWhitelist, ViewTemplates, ViewPresets:
		return true
	default:
		return false
	}
}

// rulesSubTabToView returns the ViewType for the given ACLs sub-tab index (0=Rules, 1=Templates, 2=Presets, 3=API Keys, 4=IP Whitelist).
func (m Model) rulesSubTabToView(sub int) ViewType {
	switch sub {
	case 0:
		return ViewRules
	case 1:
		return ViewTemplates
	case 2:
		return ViewPresets
	case 3:
		return ViewAPIKeys
	case 4:
		return ViewIPWhitelist
	default:
		return ViewRules
	}
}
