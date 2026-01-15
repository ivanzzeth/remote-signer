package views

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// Available rule types and modes
var ruleTypes = []string{"", "evm_address_list", "evm_contract_method", "evm_value_limit"}
var ruleModes = []string{"whitelist", "blocklist"}

// RequestDetailModel represents the request detail view
type RequestDetailModel struct {
	client        client.ClientInterface
	ctx           context.Context
	width         int
	height        int
	spinner       spinner.Model
	loading       bool
	err           error
	request       *client.RequestStatus
	previewRule   *client.Rule
	previewError  string
	showApprove   bool
	showReject    bool
	generateRule  bool
	ruleTypeIdx   int    // Index into ruleTypes
	ruleModeIdx   int    // Index into ruleModes
	ruleNameInput textinput.Model
	maxValueInput textinput.Model
	activeInput   string // "name" or "maxvalue"
	actionResult  string
	goBack        bool
}

// RequestDetailDataMsg is sent when request detail is loaded
type RequestDetailDataMsg struct {
	Request *client.RequestStatus
	Err     error
}

// PreviewRuleMsg is sent when rule preview is loaded
type PreviewRuleMsg struct {
	Rule *client.Rule
	Err  error
}

// ApprovalResultMsg is sent when approval/rejection is complete
type ApprovalResultMsg struct {
	Success bool
	Message string
	Err     error
}

// NewRequestDetailModel creates a new request detail model
func NewRequestDetailModel(c client.ClientInterface, ctx context.Context) (*RequestDetailModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	nameInput := textinput.New()
	nameInput.Placeholder = "Rule name (optional)"
	nameInput.Width = 50

	maxValueInput := textinput.New()
	maxValueInput.Placeholder = "Max value in wei (required for value_limit)"
	maxValueInput.Width = 50

	return &RequestDetailModel{
		client:        c,
		ctx:           ctx,
		spinner:       s,
		ruleNameInput: nameInput,
		maxValueInput: maxValueInput,
		ruleTypeIdx:   1, // Default to evm_address_list
		ruleModeIdx:   0, // Default to whitelist
	}, nil
}

// Init initializes the view
func (m *RequestDetailModel) Init() tea.Cmd {
	return nil
}

// SetSize sets the view size
func (m *RequestDetailModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// LoadRequest loads a request by ID
func (m *RequestDetailModel) LoadRequest(requestID string) tea.Cmd {
	m.loading = true
	m.request = nil
	m.previewRule = nil
	m.previewError = ""
	m.showApprove = false
	m.showReject = false
	m.generateRule = false
	m.ruleTypeIdx = 1 // Reset to default
	m.ruleModeIdx = 0
	m.ruleNameInput.SetValue("")
	m.maxValueInput.SetValue("")
	m.activeInput = ""
	m.actionResult = ""
	m.goBack = false

	return tea.Batch(
		m.spinner.Tick,
		m.loadRequestData(requestID),
	)
}

// ShouldGoBack returns true if the view should go back to the list
func (m *RequestDetailModel) ShouldGoBack() bool {
	return m.goBack
}

// ResetGoBack resets the go back flag
func (m *RequestDetailModel) ResetGoBack() {
	m.goBack = false
}

func (m *RequestDetailModel) loadRequestData(requestID string) tea.Cmd {
	return func() tea.Msg {
		req, err := m.client.GetRequest(m.ctx, requestID)
		if err != nil {
			return RequestDetailDataMsg{Err: err}
		}
		return RequestDetailDataMsg{Request: req, Err: nil}
	}
}

func (m *RequestDetailModel) loadPreviewRule(requestID string) tea.Cmd {
	return func() tea.Msg {
		ruleType := ruleTypes[m.ruleTypeIdx]
		if ruleType == "" {
			// No rule generation requested
			return PreviewRuleMsg{Rule: nil, Err: nil}
		}

		req := &client.PreviewRuleRequest{
			RuleType: ruleType,
			RuleMode: ruleModes[m.ruleModeIdx],
			RuleName: m.ruleNameInput.Value(),
		}
		if ruleType == "evm_value_limit" {
			req.MaxValue = m.maxValueInput.Value()
		}

		preview, err := m.client.PreviewRule(m.ctx, requestID, req)
		if err != nil {
			return PreviewRuleMsg{Err: err}
		}
		return PreviewRuleMsg{Rule: &preview.Rule, Err: nil}
	}
}

func (m *RequestDetailModel) approveRequest() tea.Cmd {
	return func() tea.Msg {
		req := &client.ApproveRequest{
			Approved: true,
		}

		// Only set rule fields if generating a rule
		if m.generateRule && m.ruleTypeIdx > 0 {
			req.RuleType = ruleTypes[m.ruleTypeIdx]
			req.RuleMode = ruleModes[m.ruleModeIdx]
			req.RuleName = m.ruleNameInput.Value()
			if req.RuleType == "evm_value_limit" {
				req.MaxValue = m.maxValueInput.Value()
			}
		}

		resp, err := m.client.ApproveSignRequest(m.ctx, m.request.ID, req)
		if err != nil {
			return ApprovalResultMsg{Success: false, Err: err}
		}

		msg := fmt.Sprintf("Request approved. Status: %s", resp.Status)
		if resp.GeneratedRule != nil {
			msg += fmt.Sprintf("\nRule created: %s (%s)", resp.GeneratedRule.Name, resp.GeneratedRule.Type)
		}
		return ApprovalResultMsg{Success: true, Message: msg, Err: nil}
	}
}

func (m *RequestDetailModel) rejectRequest() tea.Cmd {
	return func() tea.Msg {
		req := &client.ApproveRequest{
			Approved: false,
		}

		resp, err := m.client.ApproveSignRequest(m.ctx, m.request.ID, req)
		if err != nil {
			return ApprovalResultMsg{Success: false, Err: err}
		}

		return ApprovalResultMsg{
			Success: true,
			Message: fmt.Sprintf("Request rejected. Status: %s", resp.Status),
			Err:     nil,
		}
	}
}

// Update handles messages
func (m *RequestDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case RequestDetailDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.request = msg.Request
			m.err = nil
		}
		return m, nil

	case PreviewRuleMsg:
		if msg.Err != nil {
			m.previewError = msg.Err.Error()
			m.previewRule = nil
		} else {
			m.previewRule = msg.Rule
			m.previewError = ""
		}
		return m, nil

	case ApprovalResultMsg:
		m.loading = false
		if msg.Err != nil {
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err))
		} else {
			m.actionResult = styles.SuccessStyle.Render(msg.Message)
			m.showApprove = false
			m.showReject = false
			// Reload request to show updated status
			if m.request != nil {
				return m, m.loadRequestData(m.request.ID)
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
		// Handle approval dialog
		if m.showApprove {
			// Handle text input first if focused
			if m.ruleNameInput.Focused() {
				switch msg.String() {
				case "tab":
					m.ruleNameInput.Blur()
					if ruleTypes[m.ruleTypeIdx] == "evm_value_limit" {
						m.maxValueInput.Focus()
						m.activeInput = "maxvalue"
						return m, textinput.Blink
					}
					m.activeInput = ""
					return m, nil
				case "esc":
					m.ruleNameInput.Blur()
					m.activeInput = ""
					return m, nil
				default:
					var cmd tea.Cmd
					m.ruleNameInput, cmd = m.ruleNameInput.Update(msg)
					return m, cmd
				}
			}
			if m.maxValueInput.Focused() {
				switch msg.String() {
				case "tab":
					m.maxValueInput.Blur()
					m.activeInput = ""
					return m, nil
				case "esc":
					m.maxValueInput.Blur()
					m.activeInput = ""
					return m, nil
				default:
					var cmd tea.Cmd
					m.maxValueInput, cmd = m.maxValueInput.Update(msg)
					return m, cmd
				}
			}

			switch msg.String() {
			case "y":
				m.loading = true
				return m, tea.Batch(m.spinner.Tick, m.approveRequest())
			case "n", "esc":
				m.showApprove = false
				m.previewRule = nil
				m.previewError = ""
				return m, nil
			case "g":
				m.generateRule = !m.generateRule
				if !m.generateRule {
					m.previewRule = nil
					m.previewError = ""
				}
				return m, nil
			case "t":
				// Cycle through rule types
				if m.generateRule {
					m.ruleTypeIdx = (m.ruleTypeIdx + 1) % len(ruleTypes)
					if m.ruleTypeIdx == 0 {
						m.ruleTypeIdx = 1 // Skip empty type when cycling
					}
					m.previewRule = nil
					m.previewError = ""
				}
				return m, nil
			case "m":
				// Cycle through rule modes
				if m.generateRule {
					m.ruleModeIdx = (m.ruleModeIdx + 1) % len(ruleModes)
					m.previewRule = nil
					m.previewError = ""
				}
				return m, nil
			case "p":
				// Preview rule
				if m.generateRule && m.request != nil {
					return m, m.loadPreviewRule(m.request.ID)
				}
				return m, nil
			case "tab":
				if m.generateRule {
					m.ruleNameInput.Focus()
					m.activeInput = "name"
					return m, textinput.Blink
				}
				return m, nil
			}
			return m, nil
		}

		// Handle rejection dialog
		if m.showReject {
			switch msg.String() {
			case "y":
				m.loading = true
				return m, tea.Batch(m.spinner.Tick, m.rejectRequest())
			case "n", "esc":
				m.showReject = false
				return m, nil
			}
			return m, nil
		}

		// Normal key handling
		switch msg.String() {
		case "esc", "backspace":
			m.goBack = true
			return m, nil
		case "a":
			if m.request != nil && (m.request.Status == "pending" || m.request.Status == "authorizing") {
				m.showApprove = true
				m.generateRule = false
				m.ruleNameInput.SetValue("")
				// Load preview rule
				return m, m.loadPreviewRule(m.request.ID)
			}
			return m, nil
		case "x":
			if m.request != nil && (m.request.Status == "pending" || m.request.Status == "authorizing") {
				m.showReject = true
				return m, nil
			}
			return m, nil
		case "r":
			if m.request != nil {
				return m, m.LoadRequest(m.request.ID)
			}
			return m, nil
		}
	}

	return m, nil
}

// View renders the request detail view
func (m *RequestDetailModel) View() string {
	if m.loading {
		return m.renderLoading()
	}

	if m.err != nil {
		return m.renderError()
	}

	if m.showApprove {
		return m.renderApproveDialog()
	}

	if m.showReject {
		return m.renderRejectDialog()
	}

	return m.renderDetail()
}

func (m *RequestDetailModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading...", m.spinner.View()),
	)
}

func (m *RequestDetailModel) renderError() string {
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

func (m *RequestDetailModel) renderDetail() string {
	if m.request == nil {
		return "No request loaded"
	}

	var content strings.Builder

	// Title
	content.WriteString(styles.TitleStyle.Render("Request Details"))
	content.WriteString("\n\n")

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
		{"ID", m.request.ID},
		{"Status", m.request.Status},
		{"Chain Type", m.request.ChainType},
		{"Chain ID", m.request.ChainID},
		{"Signer", m.request.SignerAddress},
		{"Sign Type", m.request.SignType},
		{"API Key ID", m.request.APIKeyID},
		{"Created At", m.request.CreatedAt.Format("2006-01-02 15:04:05")},
		{"Updated At", m.request.UpdatedAt.Format("2006-01-02 15:04:05")},
	}

	if m.request.RuleMatchedID != nil {
		info = append(info, struct{ key, value string }{"Rule Matched", *m.request.RuleMatchedID})
	}
	if m.request.ApprovedBy != nil {
		info = append(info, struct{ key, value string }{"Approved By", *m.request.ApprovedBy})
	}
	if m.request.ApprovedAt != nil {
		info = append(info, struct{ key, value string }{"Approved At", m.request.ApprovedAt.Format("2006-01-02 15:04:05")})
	}
	if m.request.CompletedAt != nil {
		info = append(info, struct{ key, value string }{"Completed At", m.request.CompletedAt.Format("2006-01-02 15:04:05")})
	}
	if m.request.ErrorMessage != "" {
		info = append(info, struct{ key, value string }{"Error", m.request.ErrorMessage})
	}

	for _, item := range info {
		keyStr := styles.InfoKeyStyle.Render(item.key + ":")
		valueStr := item.value
		if item.key == "Status" {
			valueStr = styles.GetStatusStyle(item.value).Render(item.value)
		}
		content.WriteString(fmt.Sprintf("%s %s\n", keyStr, valueStr))
	}

	// Signature if completed
	if m.request.Signature != "" {
		content.WriteString("\n")
		content.WriteString(styles.SubtitleStyle.Render("Signature"))
		content.WriteString("\n")
		sig := m.request.Signature
		if len(sig) > 100 {
			sig = sig[:97] + "..."
		}
		content.WriteString(styles.MutedColor.Render(sig))
		content.WriteString("\n")
	}

	// Actions
	content.WriteString("\n")
	if m.request.Status == "pending" || m.request.Status == "authorizing" {
		content.WriteString(styles.SubtitleStyle.Render("Actions"))
		content.WriteString("\n")
		content.WriteString(styles.ButtonSuccessStyle.Render(" [a] Approve "))
		content.WriteString("  ")
		content.WriteString(styles.ButtonDangerStyle.Render(" [x] Reject "))
		content.WriteString("\n")
	}

	// Help
	content.WriteString("\n")
	helpText := "Esc: go back | r: refresh"
	if m.request.Status == "pending" || m.request.Status == "authorizing" {
		helpText = "a: approve | x: reject | " + helpText
	}
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *RequestDetailModel) renderApproveDialog() string {
	var content strings.Builder

	content.WriteString(styles.TitleStyle.Render("Approve Request"))
	content.WriteString("\n\n")

	if m.request != nil {
		content.WriteString(fmt.Sprintf("Request ID: %s\n", m.request.ID))
		content.WriteString(fmt.Sprintf("Signer: %s\n", m.request.SignerAddress))
		content.WriteString(fmt.Sprintf("Sign Type: %s\n", m.request.SignType))
	}

	content.WriteString("\n")

	// Generate rule option
	checkbox := "[ ]"
	if m.generateRule {
		checkbox = "[✓]"
	}
	content.WriteString(fmt.Sprintf("%s Generate rule from this approval (press 'g' to toggle)\n", checkbox))

	if m.generateRule {
		content.WriteString("\n")
		content.WriteString(styles.SubtitleStyle.Render("Rule Configuration"))
		content.WriteString("\n")

		// Rule type selection
		ruleType := ruleTypes[m.ruleTypeIdx]
		if ruleType == "" {
			ruleType = "(none)"
		}
		content.WriteString(fmt.Sprintf("Type [t]: %s\n", styles.InfoValueStyle.Render(ruleType)))

		// Rule mode selection
		content.WriteString(fmt.Sprintf("Mode [m]: %s\n", styles.InfoValueStyle.Render(ruleModes[m.ruleModeIdx])))

		// Rule name input
		content.WriteString("\nRule name [Tab]: ")
		content.WriteString(m.ruleNameInput.View())
		content.WriteString("\n")

		// Max value input (only for evm_value_limit)
		if ruleTypes[m.ruleTypeIdx] == "evm_value_limit" {
			content.WriteString("\nMax value (wei) [Tab]: ")
			content.WriteString(m.maxValueInput.View())
			content.WriteString("\n")
		}

		// Preview button
		content.WriteString("\n")
		content.WriteString(styles.ButtonStyle.Render(" [p] Preview Rule "))
		content.WriteString("\n")

		// Preview result
		if m.previewError != "" {
			content.WriteString("\n")
			content.WriteString(styles.ErrorStyle.Render(fmt.Sprintf("Preview Error: %s", m.previewError)))
			content.WriteString("\n")
		} else if m.previewRule != nil {
			content.WriteString("\n")
			content.WriteString(styles.SubtitleStyle.Render("Rule Preview"))
			content.WriteString("\n")
			content.WriteString(fmt.Sprintf("Name: %s\n", m.previewRule.Name))
			content.WriteString(fmt.Sprintf("Type: %s\n", m.previewRule.Type))
			content.WriteString(fmt.Sprintf("Mode: %s\n", m.previewRule.Mode))
			if m.previewRule.Config != nil {
				configJSON, err := json.MarshalIndent(m.previewRule.Config, "", "  ")
				if err == nil {
					content.WriteString(fmt.Sprintf("Config:\n%s\n", string(configJSON)))
				}
			}
		}
	}

	content.WriteString("\n")
	content.WriteString(styles.SubtitleStyle.Render("Confirm approval?"))
	content.WriteString("\n")
	content.WriteString(styles.ButtonSuccessStyle.Render(" [y] Yes "))
	content.WriteString("  ")
	content.WriteString(styles.ButtonStyle.Render(" [n] No "))
	content.WriteString("\n\n")

	helpText := "y: confirm | n/Esc: cancel | g: toggle rule generation"
	if m.generateRule {
		helpText += " | t: type | m: mode | p: preview | Tab: input"
	}
	content.WriteString(styles.HelpStyle.Render(helpText))

	return styles.BoxStyle.Render(content.String())
}

func (m *RequestDetailModel) renderRejectDialog() string {
	var content strings.Builder

	content.WriteString(styles.TitleStyle.Render("Reject Request"))
	content.WriteString("\n\n")

	if m.request != nil {
		content.WriteString(fmt.Sprintf("Request ID: %s\n", m.request.ID))
		content.WriteString(fmt.Sprintf("Signer: %s\n", m.request.SignerAddress))
		content.WriteString(fmt.Sprintf("Sign Type: %s\n", m.request.SignType))
	}

	content.WriteString("\n")
	content.WriteString(styles.ErrorStyle.Render("Are you sure you want to reject this request?"))
	content.WriteString("\n\n")
	content.WriteString(styles.ButtonDangerStyle.Render(" [y] Yes, Reject "))
	content.WriteString("  ")
	content.WriteString(styles.ButtonStyle.Render(" [n] No, Cancel "))
	content.WriteString("\n\n")
	content.WriteString(styles.HelpStyle.Render("y: confirm rejection | n/Esc: cancel"))

	return styles.BoxStyle.Render(content.String())
}
