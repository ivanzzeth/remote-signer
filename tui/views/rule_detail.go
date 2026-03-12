package views

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// RuleDetailModel represents the rule detail view
type RuleDetailModel struct {
	rules_svc    evm.RuleAPI
	ctx          context.Context
	width        int
	height       int
	spinner      spinner.Model
	viewport     viewport.Model
	loading      bool
	err          error
	rule         *evm.Rule
	budgets      []evm.RuleBudget
	budgetsErr   error
	showDelete   bool
	showToggle   bool
	actionResult string
	goBack       bool
	ready        bool
}

// RuleDetailDataMsg is sent when rule detail is loaded
type RuleDetailDataMsg struct {
	Rule *evm.Rule
	Err  error
}

// RuleDetailActionMsg is sent when a rule action is complete
type RuleDetailActionMsg struct {
	Action  string
	Success bool
	Message string
	Err     error
}

// RuleBudgetsDataMsg is sent when budgets for the rule are loaded
type RuleBudgetsDataMsg struct {
	Budgets []evm.RuleBudget
	Err     error
}

// NewRuleDetailModel creates a new rule detail model
func NewRuleDetailModel(c *client.Client, ctx context.Context) (*RuleDetailModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newRuleDetailModelFromService(c.EVM.Rules, ctx)
}

// newRuleDetailModelFromService creates a rule detail model from a RuleAPI (for testing).
func newRuleDetailModelFromService(svc evm.RuleAPI, ctx context.Context) (*RuleDetailModel, error) {
	if svc == nil {
		return nil, fmt.Errorf("client is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	return &RuleDetailModel{
		rules_svc: svc,
		ctx:       ctx,
		spinner:   s,
	}, nil
}

// Init initializes the view
func (m *RuleDetailModel) Init() tea.Cmd {
	return nil
}

// SetSize sets the view size
func (m *RuleDetailModel) SetSize(width, height int) {
	m.width = width
	m.height = height

	// Reserve space for header and footer
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

// LoadRule loads a rule by ID
func (m *RuleDetailModel) LoadRule(ruleID string) tea.Cmd {
	m.loading = true
	m.rule = nil
	m.budgets = nil
	m.budgetsErr = nil
	m.showDelete = false
	m.showToggle = false
	m.actionResult = ""
	m.goBack = false

	return tea.Batch(
		m.spinner.Tick,
		m.loadRuleData(ruleID),
		m.loadBudgetsData(ruleID),
	)
}

func (m *RuleDetailModel) loadBudgetsData(ruleID string) tea.Cmd {
	return func() tea.Msg {
		budgets, err := m.rules_svc.ListBudgets(m.ctx, ruleID)
		if err != nil {
			return RuleBudgetsDataMsg{Err: err}
		}
		return RuleBudgetsDataMsg{Budgets: budgets, Err: nil}
	}
}

// ShouldGoBack returns true if the view should go back to the list
func (m *RuleDetailModel) ShouldGoBack() bool {
	return m.goBack
}

// ResetGoBack resets the go back flag
func (m *RuleDetailModel) ResetGoBack() {
	m.goBack = false
}

func (m *RuleDetailModel) loadRuleData(ruleID string) tea.Cmd {
	return func() tea.Msg {
		rule, err := m.rules_svc.Get(m.ctx, ruleID)
		if err != nil {
			return RuleDetailDataMsg{Err: err}
		}
		return RuleDetailDataMsg{Rule: rule, Err: nil}
	}
}

func (m *RuleDetailModel) toggleRule() tea.Cmd {
	return func() tea.Msg {
		rule, err := m.rules_svc.Toggle(m.ctx, m.rule.ID, !m.rule.Enabled)
		if err != nil {
			return RuleDetailActionMsg{Action: "toggle", Success: false, Err: err}
		}
		action := "enabled"
		if !rule.Enabled {
			action = "disabled"
		}
		return RuleDetailActionMsg{
			Action:  "toggle",
			Success: true,
			Message: fmt.Sprintf("Rule %s", action),
			Err:     nil,
		}
	}
}

func (m *RuleDetailModel) deleteRule() tea.Cmd {
	return func() tea.Msg {
		err := m.rules_svc.Delete(m.ctx, m.rule.ID)
		if err != nil {
			return RuleDetailActionMsg{Action: "delete", Success: false, Err: err}
		}
		return RuleDetailActionMsg{
			Action:  "delete",
			Success: true,
			Message: "Rule deleted",
			Err:     nil,
		}
	}
}

// Update handles messages
func (m *RuleDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case RuleDetailDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.rule = msg.Rule
			m.err = nil
		}
		return m, nil

	case RuleBudgetsDataMsg:
		if msg.Err != nil {
			m.budgetsErr = msg.Err
			m.budgets = nil
		} else {
			m.budgets = msg.Budgets
			m.budgetsErr = nil
		}
		return m, nil

	case RuleDetailActionMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.showDelete = false
			m.showToggle = false
			if msg.Action == "delete" {
				m.goBack = true
			} else {
				// Reload rule to show updated status
				if m.rule != nil {
					return m, m.loadRuleData(m.rule.ID)
				}
			}
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
		// Handle delete confirmation
		if m.showDelete {
			switch msg.String() {
			case "y":
				m.loading = true
				m.showDelete = false
				return m, tea.Batch(m.spinner.Tick, m.deleteRule())
			case "n", "esc":
				m.showDelete = false
				return m, nil
			}
			return m, nil
		}

		// Handle toggle confirmation
		if m.showToggle {
			switch msg.String() {
			case "y":
				m.loading = true
				m.showToggle = false
				return m, tea.Batch(m.spinner.Tick, m.toggleRule())
			case "n", "esc":
				m.showToggle = false
				return m, nil
			}
			return m, nil
		}

		// Normal key handling
		switch msg.String() {
		case "esc", "backspace":
			m.goBack = true
			return m, nil
		case "t":
			if m.rule != nil {
				m.showToggle = true
			}
			return m, nil
		case "d":
			if m.rule != nil {
				m.showDelete = true
			}
			return m, nil
		case "r":
			if m.rule != nil {
				return m, m.LoadRule(m.rule.ID)
			}
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

// View renders the rule detail view
func (m *RuleDetailModel) View() string {
	if m.loading {
		return m.renderLoading()
	}

	if m.err != nil {
		return m.renderError()
	}

	if m.showDelete {
		return m.renderDeleteConfirm()
	}

	if m.showToggle {
		return m.renderToggleConfirm()
	}

	return m.renderDetail()
}

func (m *RuleDetailModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading...", m.spinner.View()),
	)
}

func (m *RuleDetailModel) renderError() string {
	errBox := styles.BoxStyle.
		BorderForeground(styles.ErrorColor).
		Render(fmt.Sprintf("Error: %v\n\nPress Esc to go back", m.err))

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		errBox,
	)
}

// formatRuleConfigForDisplay formats rule config for TUI display. Long string fields
// (e.g. "script", "expression") are rendered with newlines so the full content
// is visible when scrolling the viewport.
func formatRuleConfigForDisplay(cfg map[string]interface{}) string {
	if cfg == nil {
		return "{}"
	}
	const indent = "  "
	var b strings.Builder
	b.WriteString("{\n")
	// Output non-script keys first, then script/expression last for readability
	scriptKeys := []string{"script", "expression"}
	for k, v := range cfg {
		isScriptKey := (k == "script" || k == "expression")
		if isScriptKey {
			continue
		}
		writeConfigEntry(&b, indent, k, v)
	}
	for _, k := range scriptKeys {
		if v, ok := cfg[k]; ok {
			writeConfigEntry(&b, indent, k, v)
		}
	}
	b.WriteString("}")
	return b.String()
}

func writeConfigEntry(b *strings.Builder, indent, k string, v interface{}) {
	switch val := v.(type) {
	case string:
		if (k == "script" || k == "expression") && len(val) > 0 {
			b.WriteString(indent)
			b.WriteString(fmt.Sprintf("%q:\n", k))
			lines := strings.Split(val, "\n")
			for _, line := range lines {
				b.WriteString(indent)
				b.WriteString(indent)
				b.WriteString(line)
				b.WriteString("\n")
			}
		} else {
			b.WriteString(indent)
			b.WriteString(fmt.Sprintf("%q: %q\n", k, val))
		}
	default:
		sub, err := json.MarshalIndent(v, indent, indent)
		if err != nil {
			b.WriteString(indent)
			b.WriteString(fmt.Sprintf("%q: %v\n", k, v))
		} else {
			b.WriteString(indent)
			b.WriteString(fmt.Sprintf("%q: ", k))
			b.WriteString(strings.TrimPrefix(string(sub), indent))
			b.WriteString("\n")
		}
	}
}

func (m *RuleDetailModel) renderDetail() string {
	if m.rule == nil {
		return "No rule loaded"
	}

	var content strings.Builder

	// Action result message
	if m.actionResult != "" {
		content.WriteString(m.actionResult)
		content.WriteString("\n\n")
	}

	// Basic info
	info := []struct {
		key   string
		value string
	}{
		{"ID", m.rule.ID},
		{"Name", m.rule.Name},
		{"Description", m.rule.Description},
		{"Type", m.rule.Type},
		{"Mode", m.rule.Mode},
		{"Source", m.rule.Source},
		{"Enabled", fmt.Sprintf("%t", m.rule.Enabled)},
		{"Match Count", fmt.Sprintf("%d", m.rule.MatchCount)},
		{"Created At", m.rule.CreatedAt.Format("2006-01-02 15:04:05")},
		{"Updated At", m.rule.UpdatedAt.Format("2006-01-02 15:04:05")},
	}

	if m.rule.ChainType != nil {
		info = append(info, struct{ key, value string }{"Chain Type", *m.rule.ChainType})
	}
	if m.rule.ChainID != nil {
		info = append(info, struct{ key, value string }{"Chain ID", *m.rule.ChainID})
	}
	if m.rule.APIKeyID != nil {
		info = append(info, struct{ key, value string }{"API Key ID", *m.rule.APIKeyID})
	}
	if m.rule.SignerAddress != nil {
		info = append(info, struct{ key, value string }{"Signer", *m.rule.SignerAddress})
	}
	if m.rule.LastMatchedAt != nil {
		info = append(info, struct{ key, value string }{"Last Matched", m.rule.LastMatchedAt.Format("2006-01-02 15:04:05")})
	}
	if m.rule.ExpiresAt != nil {
		info = append(info, struct{ key, value string }{"Expires At", m.rule.ExpiresAt.Format("2006-01-02 15:04:05")})
	}

	for _, item := range info {
		if item.value == "" {
			continue
		}
		keyStr := styles.InfoKeyStyle.Render(item.key + ":")
		valueStr := item.value
		if item.key == "Mode" {
			if item.value == "whitelist" {
				valueStr = styles.SuccessStyle.Render(item.value)
			} else {
				valueStr = styles.ErrorStyle.Render(item.value)
			}
		}
		if item.key == "Enabled" {
			if item.value == "true" {
				valueStr = styles.SuccessStyle.Render("Yes")
			} else {
				valueStr = styles.MutedColor.Render("No")
			}
		}
		content.WriteString(fmt.Sprintf("%s %s\n", keyStr, valueStr))
	}

	// Budgets
	content.WriteString("\n")
	content.WriteString(styles.SubtitleStyle.Render("Budgets"))
	content.WriteString("\n")
	if m.budgetsErr != nil {
		content.WriteString(styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.budgetsErr)))
		content.WriteString("\n")
	} else if len(m.budgets) == 0 {
		content.WriteString(styles.MutedColor.Render("No budgets"))
		content.WriteString("\n")
	} else {
		for _, b := range m.budgets {
			content.WriteString(fmt.Sprintf("  %s: spent %s / %s (max/tx: %s, tx count: %d)\n",
				b.Unit, b.Spent, b.MaxTotal, b.MaxPerTx, b.TxCount))
		}
	}

	// Config
	if len(m.rule.Config) > 0 {
		content.WriteString("\n")
		content.WriteString(styles.SubtitleStyle.Render("Configuration"))
		content.WriteString("\n")
		var cfg map[string]interface{}
		if err := json.Unmarshal(m.rule.Config, &cfg); err == nil {
			configStr := formatRuleConfigForDisplay(cfg)
			content.WriteString(styles.MutedColor.Render(configStr))
		} else {
			content.WriteString(styles.MutedColor.Render(string(m.rule.Config)))
		}
		content.WriteString("\n")
	}

	// Actions
	content.WriteString("\n")
	content.WriteString(styles.SubtitleStyle.Render("Actions"))
	content.WriteString("\n")
	if m.rule.Enabled {
		content.WriteString(styles.ButtonStyle.Render(" [t] Disable "))
	} else {
		content.WriteString(styles.ButtonSuccessStyle.Render(" [t] Enable "))
	}
	content.WriteString("  ")
	content.WriteString(styles.ButtonDangerStyle.Render(" [d] Delete "))
	content.WriteString("\n")

	// Set content in viewport
	m.viewport.SetContent(content.String())

	// Build final view with header, viewport, and footer
	var view strings.Builder

	// Header
	view.WriteString(styles.TitleStyle.Render("Rule Details"))
	view.WriteString("\n\n")

	// Viewport (scrollable content)
	view.WriteString(m.viewport.View())
	view.WriteString("\n")

	// Footer with scroll info and help
	scrollInfo := fmt.Sprintf("(%d%% scrolled)", int(m.viewport.ScrollPercent()*100))
	helpText := "j/k: scroll | t: toggle | d: delete | r: refresh | Esc: back"
	view.WriteString(styles.HelpStyle.Render(fmt.Sprintf("%s  %s", scrollInfo, helpText)))

	return view.String()
}

func (m *RuleDetailModel) renderDeleteConfirm() string {
	var content strings.Builder

	content.WriteString(styles.TitleStyle.Render("Delete Rule"))
	content.WriteString("\n\n")

	if m.rule != nil {
		content.WriteString(fmt.Sprintf("Rule ID: %s\n", m.rule.ID))
		content.WriteString(fmt.Sprintf("Name: %s\n", m.rule.Name))
		content.WriteString(fmt.Sprintf("Type: %s\n", m.rule.Type))
	}

	content.WriteString("\n")
	content.WriteString(styles.ErrorStyle.Render("Are you sure you want to delete this rule?"))
	content.WriteString("\n")
	content.WriteString(styles.ErrorStyle.Render("This action cannot be undone."))
	content.WriteString("\n\n")
	content.WriteString(styles.ButtonDangerStyle.Render(" [y] Yes, Delete "))
	content.WriteString("  ")
	content.WriteString(styles.ButtonStyle.Render(" [n] No, Cancel "))

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}

func (m *RuleDetailModel) renderToggleConfirm() string {
	var content strings.Builder

	action := "Enable"
	if m.rule != nil && m.rule.Enabled {
		action = "Disable"
	}

	content.WriteString(styles.TitleStyle.Render(fmt.Sprintf("%s Rule", action)))
	content.WriteString("\n\n")

	if m.rule != nil {
		content.WriteString(fmt.Sprintf("Rule ID: %s\n", m.rule.ID))
		content.WriteString(fmt.Sprintf("Name: %s\n", m.rule.Name))
		content.WriteString(fmt.Sprintf("Currently: %s\n", map[bool]string{true: "Enabled", false: "Disabled"}[m.rule.Enabled]))
	}

	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("Do you want to %s this rule?", strings.ToLower(action)))
	content.WriteString("\n\n")
	content.WriteString(styles.ButtonActiveStyle.Render(fmt.Sprintf(" [y] Yes, %s ", action)))
	content.WriteString("  ")
	content.WriteString(styles.ButtonStyle.Render(" [n] No, Cancel "))

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		styles.BoxStyle.Render(content.String()),
	)
}
