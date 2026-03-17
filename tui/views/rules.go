package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// RulesModel represents the rules list view
type RulesModel struct {
	rules_svc    evm.RuleAPI
	ctx          context.Context
	width        int
	height       int
	spinner      spinner.Model
	loading      bool
	err          error
	rules        []evm.Rule
	total        int
	selectedIdx  int
	offset       int
	limit        int
	typeFilter   string
	modeFilter   string
	showFilter   bool
	filterInput  textinput.Model
	filterType   string // "type" or "mode"
	showDelete   bool
	actionResult string
}

// RulesDataMsg is sent when rules data is loaded
type RulesDataMsg struct {
	Rules []evm.Rule
	Total int
	Err   error
}

// RuleActionMsg is sent when a rule action is complete
type RuleActionMsg struct {
	Action  string
	Success bool
	Message string
	Err     error
}

// NewRulesModel creates a new rules model
func NewRulesModel(c *client.Client, ctx context.Context) (*RulesModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newRulesModelFromService(c.EVM.Rules, ctx)
}

// newRulesModelFromService creates a rules model from a RuleAPI (for testing).
func newRulesModelFromService(svc evm.RuleAPI, ctx context.Context) (*RulesModel, error) {
	if svc == nil {
		return nil, fmt.Errorf("client is required")
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

	return &RulesModel{
		rules_svc:   svc,
		ctx:         ctx,
		spinner:     s,
		loading:     true,
		limit:       20,
		filterInput: ti,
	}, nil
}

// Init initializes the rules view
func (m *RulesModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size
func (m *RulesModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh refreshes the rules data
func (m *RulesModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// GetSelectedRuleID returns the ID of the selected rule
func (m *RulesModel) GetSelectedRuleID() string {
	if len(m.rules) == 0 || m.selectedIdx >= len(m.rules) {
		return ""
	}
	return m.rules[m.selectedIdx].ID
}

func (m *RulesModel) loadData() tea.Cmd {
	return func() tea.Msg {
		filter := &evm.ListRulesFilter{
			Type:   m.typeFilter,
			Mode:   m.modeFilter,
			Limit:  m.limit,
			Offset: m.offset,
		}

		resp, err := m.rules_svc.List(m.ctx, filter)
		if err != nil {
			return RulesDataMsg{Err: err}
		}
		return RulesDataMsg{Rules: resp.Rules, Total: resp.Total, Err: nil}
	}
}

func (m *RulesModel) toggleRule(ruleID string, enabled bool) tea.Cmd {
	return func() tea.Msg {
		rule, err := m.rules_svc.Toggle(m.ctx, ruleID, enabled)
		if err != nil {
			return RuleActionMsg{Action: "toggle", Success: false, Err: err}
		}
		action := "enabled"
		if !rule.Enabled {
			action = "disabled"
		}
		return RuleActionMsg{
			Action:  "toggle",
			Success: true,
			Message: fmt.Sprintf("Rule %s", action),
			Err:     nil,
		}
	}
}

func (m *RulesModel) deleteRule(ruleID string) tea.Cmd {
	return func() tea.Msg {
		err := m.rules_svc.Delete(m.ctx, ruleID)
		if err != nil {
			return RuleActionMsg{Action: "delete", Success: false, Err: err}
		}
		return RuleActionMsg{
			Action:  "delete",
			Success: true,
			Message: "Rule deleted",
			Err:     nil,
		}
	}
}

// Update handles messages
func (m *RulesModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case RulesDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.rules = msg.Rules
			m.total = msg.Total
			m.err = nil
		}
		return m, nil

	case RuleActionMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.showDelete = false
			// Refresh the list
			return m, m.Refresh()
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
				if len(m.rules) > 0 && m.selectedIdx < len(m.rules) {
					ruleID := m.rules[m.selectedIdx].ID
					m.loading = true
					m.showDelete = false
					return m, tea.Batch(m.spinner.Tick, m.deleteRule(ruleID))
				}
				m.showDelete = false
				return m, nil
			case "n", "esc":
				m.showDelete = false
				return m, nil
			}
			return m, nil
		}

		// Handle filter input
		if m.showFilter {
			switch msg.String() {
			case "enter":
				if m.filterType == "type" {
					m.typeFilter = m.filterInput.Value()
				} else if m.filterType == "mode" {
					m.modeFilter = m.filterInput.Value()
				}
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

		// Normal key handling
		switch msg.String() {
		case "r":
			return m, m.Refresh()
		case "f":
			m.showFilter = true
			m.filterType = "type"
			m.filterInput.Placeholder = "Rule type (e.g., evm_address_list, evm_value_limit)"
			m.filterInput.Focus()
			return m, textinput.Blink
		case "m":
			m.showFilter = true
			m.filterType = "mode"
			m.filterInput.Placeholder = "Rule mode (whitelist or blocklist)"
			m.filterInput.Focus()
			return m, textinput.Blink
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.selectedIdx < len(m.rules)-1 {
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
			if m.selectedIdx >= len(m.rules) {
				m.selectedIdx = len(m.rules) - 1
			}
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			return m, nil
		case "home", "g":
			m.selectedIdx = 0
			return m, nil
		case "end", "G":
			if len(m.rules) > 0 {
				m.selectedIdx = len(m.rules) - 1
			}
			return m, nil
		case "t":
			// Toggle enabled
			if len(m.rules) > 0 && m.selectedIdx < len(m.rules) {
				rule := m.rules[m.selectedIdx]
				m.loading = true
				return m, tea.Batch(m.spinner.Tick, m.toggleRule(rule.ID, !rule.Enabled))
			}
			return m, nil
		case "d":
			// Delete rule
			if len(m.rules) > 0 && m.selectedIdx < len(m.rules) {
				m.showDelete = true
			}
			return m, nil
		case "n":
			// Next page
			if m.offset+m.limit < m.total {
				m.offset += m.limit
				m.selectedIdx = 0
				return m, m.Refresh()
			}
			return m, nil
		case "p":
			// Previous page
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
			// Clear filters
			m.typeFilter = ""
			m.modeFilter = ""
			m.filterInput.SetValue("")
			m.offset = 0
			m.selectedIdx = 0
			return m, m.Refresh()
		}
	}

	return m, nil
}

// View renders the rules view
func (m *RulesModel) View() string {
	if m.showDelete {
		return m.renderDeleteConfirm()
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

	return m.renderRules()
}

// IsCapturingInput returns true when this view is capturing keyboard input (filter active).
func (m *RulesModel) IsCapturingInput() bool {
	return m.showFilter
}

func (m *RulesModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading rules...", m.spinner.View()),
	)
}

func (m *RulesModel) renderError() string {
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

func (m *RulesModel) renderFilterInput() string {
	var content strings.Builder

	filterTitle := "Filter by Type"
	if m.filterType == "mode" {
		filterTitle = "Filter by Mode"
	}

	content.WriteString(styles.SubtitleStyle.Render(filterTitle))
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

func (m *RulesModel) renderDeleteConfirm() string {
	var content strings.Builder

	content.WriteString(styles.TitleStyle.Render("Delete Rule"))
	content.WriteString("\n\n")

	if len(m.rules) > 0 && m.selectedIdx < len(m.rules) {
		rule := m.rules[m.selectedIdx]
		content.WriteString(fmt.Sprintf("Rule ID: %s\n", rule.ID))
		content.WriteString(fmt.Sprintf("Name: %s\n", rule.Name))
		content.WriteString(fmt.Sprintf("Type: %s\n", rule.Type))
	}

	content.WriteString("\n")
	content.WriteString(styles.ErrorStyle.Render("Are you sure you want to delete this rule?"))
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

func (m *RulesModel) renderRules() string {
	var content strings.Builder

	// Header
	header := styles.SubtitleStyle.Render("Authorization Rules")
	filters := []string{}
	if m.typeFilter != "" {
		filters = append(filters, fmt.Sprintf("type=%s", m.typeFilter))
	}
	if m.modeFilter != "" {
		filters = append(filters, fmt.Sprintf("mode=%s", m.modeFilter))
	}
	if len(filters) > 0 {
		header += styles.MutedColor.Render(fmt.Sprintf(" (filtered: %s)", strings.Join(filters, ", ")))
	}
	content.WriteString(header)
	content.WriteString("\n\n")

	// Action result
	if m.actionResult != "" {
		content.WriteString(m.actionResult)
		content.WriteString("\n\n")
	}

	// Table header
	headerRow := fmt.Sprintf("%-20s  %-24s  %-18s  %-10s  %-10s  %-8s  %-3s",
		"ID", "Name", "Type", "Mode", "Owner", "Status", "On")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	// Rows
	if len(m.rules) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No rules found"))
	} else {
		for i, rule := range m.rules {
			row := m.renderRuleRow(rule, i == m.selectedIdx)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	// Pagination info
	content.WriteString("\n")
	startIdx := m.offset + 1
	endIdx := m.offset + len(m.rules)
	if endIdx > m.total {
		endIdx = m.total
	}
	if len(m.rules) == 0 {
		startIdx = 0
		endIdx = 0
	}
	pagination := fmt.Sprintf("Showing %d-%d of %d", startIdx, endIdx, m.total)
	content.WriteString(styles.MutedColor.Render(pagination))

	// Help
	content.WriteString("\n\n")
	helpText := "↑/↓: navigate | Enter: view details | t: toggle | d: delete | f: filter type | m: filter mode | c: clear | n/p: next/prev | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *RulesModel) renderRuleRow(rule evm.Rule, selected bool) string {
	// Truncate values for display
	id := rule.ID
	if len(id) > 20 {
		id = id[:17] + "..."
	}

	name := rule.Name
	if len(name) > 24 {
		name = name[:21] + "..."
	}

	ruleType := rule.Type
	if len(ruleType) > 18 {
		ruleType = ruleType[:15] + "..."
	}

	owner := "-"
	if rule.Owner != nil {
		owner = *rule.Owner
	}
	if len(owner) > 10 {
		owner = owner[:7] + "..."
	}

	status := rule.Status
	if status == "pending_approval" {
		status = "pending"
	}
	if status == "" {
		status = "active"
	}

	enabled := "Yes"
	if !rule.Enabled {
		enabled = "No"
	}

	row := fmt.Sprintf("%-20s  %-24s  %-18s  %-10s  %-10s  %-8s  %-3s",
		id, name, ruleType, rule.Mode, owner, status, enabled,
	)

	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}

	// Color mode
	modeStyle := styles.SuccessStyle
	if rule.Mode == "blocklist" {
		modeStyle = styles.ErrorStyle
	}
	modePart := modeStyle.Render(fmt.Sprintf("%-10s", rule.Mode))

	// Color status
	statusStyle := styles.SuccessStyle
	switch status {
	case "pending":
		statusStyle = styles.WarningStyle
	case "rejected":
		statusStyle = styles.ErrorStyle
	}
	statusPart := statusStyle.Render(fmt.Sprintf("%-8s", status))

	// Color enabled
	enabledStyle := styles.SuccessStyle
	if !rule.Enabled {
		enabledStyle = styles.MutedColor
	}
	enabledPart := enabledStyle.Render(fmt.Sprintf("%-3s", enabled))

	row = fmt.Sprintf("%-20s  %-24s  %-18s  %s  %-10s  %s  %s",
		id, name, ruleType, modePart, owner, statusPart, enabledPart,
	)

	return styles.TableRowStyle.Render(row)
}
