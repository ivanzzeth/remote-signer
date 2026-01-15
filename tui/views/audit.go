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

// AuditModel represents the audit logs view
type AuditModel struct {
	client         client.ClientInterface
	ctx            context.Context
	width          int
	height         int
	spinner        spinner.Model
	loading        bool
	err            error
	records        []client.AuditRecord
	total          int
	selectedIdx    int
	limit          int
	eventFilter    string
	severityFilter string
	showFilter     bool
	filterInput    textinput.Model
	filterType     string // "event" or "severity"
	showDetail     bool
	detailScroll   int // scroll offset for detail view
	// Cursor-based pagination
	cursor        *string
	cursorID      *string
	nextCursor    *string
	nextCursorID  *string
	cursorHistory []auditCursorState
	hasMore       bool
}

// auditCursorState stores cursor position for pagination history
type auditCursorState struct {
	cursor   *string
	cursorID *string
}

// AuditDataMsg is sent when audit data is loaded
type AuditDataMsg struct {
	Records      []client.AuditRecord
	Total        int
	NextCursor   *string
	NextCursorID *string
	HasMore      bool
	Err          error
}

// NewAuditModel creates a new audit model
func NewAuditModel(c client.ClientInterface, ctx context.Context) (*AuditModel, error) {
	if c == nil {
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
	ti.Width = 50

	return &AuditModel{
		client:      c,
		ctx:         ctx,
		spinner:     s,
		loading:     true,
		limit:       30,
		filterInput: ti,
	}, nil
}

// Init initializes the audit view
func (m *AuditModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size
func (m *AuditModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh refreshes the audit data
func (m *AuditModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// resetPagination resets cursor state to first page
func (m *AuditModel) resetPagination() {
	m.cursor = nil
	m.cursorID = nil
	m.nextCursor = nil
	m.nextCursorID = nil
	m.cursorHistory = nil
	m.selectedIdx = 0
	m.hasMore = false
}

func (m *AuditModel) loadData() tea.Cmd {
	return func() tea.Msg {
		filter := &client.ListAuditFilter{
			EventType: m.eventFilter,
			Severity:  m.severityFilter,
			Limit:     m.limit,
			Cursor:    m.cursor,
			CursorID:  m.cursorID,
		}

		resp, err := m.client.ListAuditRecords(m.ctx, filter)
		if err != nil {
			return AuditDataMsg{Err: err}
		}
		return AuditDataMsg{
			Records:      resp.Records,
			Total:        resp.Total,
			NextCursor:   resp.NextCursor,
			NextCursorID: resp.NextCursorID,
			HasMore:      resp.HasMore,
			Err:          nil,
		}
	}
}

// Update handles messages
func (m *AuditModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case AuditDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.records = msg.Records
			m.total = msg.Total
			m.hasMore = msg.HasMore
			// Store next page cursor (don't overwrite current cursor)
			m.nextCursor = msg.NextCursor
			m.nextCursorID = msg.NextCursorID
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
		// Handle detail view
		if m.showDetail {
			switch msg.String() {
			case "esc", "enter", "backspace":
				m.showDetail = false
				m.detailScroll = 0
				return m, nil
			case "up", "k":
				if m.detailScroll > 0 {
					m.detailScroll--
				}
				return m, nil
			case "down", "j":
				m.detailScroll++
				return m, nil
			case "pgup", "ctrl+u":
				m.detailScroll -= 10
				if m.detailScroll < 0 {
					m.detailScroll = 0
				}
				return m, nil
			case "pgdown", "ctrl+d":
				m.detailScroll += 10
				return m, nil
			case "home", "g":
				m.detailScroll = 0
				return m, nil
			}
			return m, nil
		}

		// Handle filter input
		if m.showFilter {
			switch msg.String() {
			case "enter":
				if m.filterType == "event" {
					m.eventFilter = m.filterInput.Value()
				} else if m.filterType == "severity" {
					m.severityFilter = m.filterInput.Value()
				}
				m.showFilter = false
				m.filterInput.Blur()
				m.resetPagination()
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
		case "e":
			m.showFilter = true
			m.filterType = "event"
			m.filterInput.Placeholder = "Event type (e.g., sign_request, sign_complete, approval_granted)"
			m.filterInput.Focus()
			return m, textinput.Blink
		case "s":
			m.showFilter = true
			m.filterType = "severity"
			m.filterInput.Placeholder = "Severity (info, warning, critical)"
			m.filterInput.Focus()
			return m, textinput.Blink
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.selectedIdx < len(m.records)-1 {
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
			if m.selectedIdx >= len(m.records) {
				m.selectedIdx = len(m.records) - 1
			}
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			return m, nil
		case "home", "g":
			m.selectedIdx = 0
			return m, nil
		case "end", "G":
			if len(m.records) > 0 {
				m.selectedIdx = len(m.records) - 1
			}
			return m, nil
		case "enter":
			if len(m.records) > 0 && m.selectedIdx < len(m.records) {
				m.showDetail = true
			}
			return m, nil
		case "n":
			// Next page
			if m.hasMore && m.nextCursor != nil {
				// Save current cursor to history for going back
				m.cursorHistory = append(m.cursorHistory, auditCursorState{
					cursor:   m.cursor,
					cursorID: m.cursorID,
				})
				// Use next cursor
				m.cursor = m.nextCursor
				m.cursorID = m.nextCursorID
				m.selectedIdx = 0
				return m, m.Refresh()
			}
			return m, nil
		case "p":
			// Previous page
			if len(m.cursorHistory) > 0 {
				// Pop from history
				prev := m.cursorHistory[len(m.cursorHistory)-1]
				m.cursorHistory = m.cursorHistory[:len(m.cursorHistory)-1]
				m.cursor = prev.cursor
				m.cursorID = prev.cursorID
				m.selectedIdx = 0
				return m, m.Refresh()
			}
			return m, nil
		case "c":
			// Clear filters
			m.eventFilter = ""
			m.severityFilter = ""
			m.filterInput.SetValue("")
			m.resetPagination()
			return m, m.Refresh()
		}
	}

	return m, nil
}

// View renders the audit view
func (m *AuditModel) View() string {
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

	return m.renderAuditLogs()
}

func (m *AuditModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading audit logs...", m.spinner.View()),
	)
}

func (m *AuditModel) renderError() string {
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

func (m *AuditModel) renderFilterInput() string {
	var content strings.Builder

	filterTitle := "Filter by Event Type"
	if m.filterType == "severity" {
		filterTitle = "Filter by Severity"
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

func (m *AuditModel) renderAuditLogs() string {
	var content strings.Builder

	// Header
	header := styles.SubtitleStyle.Render("Audit Logs")
	filters := []string{}
	if m.eventFilter != "" {
		filters = append(filters, fmt.Sprintf("event=%s", m.eventFilter))
	}
	if m.severityFilter != "" {
		filters = append(filters, fmt.Sprintf("severity=%s", m.severityFilter))
	}
	if len(filters) > 0 {
		header += styles.MutedColor.Render(fmt.Sprintf(" (filtered: %s)", strings.Join(filters, ", ")))
	}
	content.WriteString(header)
	content.WriteString("\n\n")

	// Table header
	headerRow := fmt.Sprintf("%-20s  %-10s  %-20s  %-42s  %-24s",
		"Timestamp", "Severity", "Event Type", "Signer/Request", "Details")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	// Rows
	if len(m.records) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No audit records found"))
	} else {
		for i, record := range m.records {
			row := m.renderAuditRow(record, i == m.selectedIdx)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	// Pagination info
	content.WriteString("\n")
	pageNum := len(m.cursorHistory) + 1
	pagination := fmt.Sprintf("Page %d | Showing %d items | Total: %d", pageNum, len(m.records), m.total)
	if m.hasMore {
		pagination += " | More available"
	}
	content.WriteString(styles.MutedColor.Render(pagination))

	// Debug: show cursor info
	content.WriteString("\n")
	cursorInfo := "Cursor: "
	if m.cursor != nil {
		cursorInfo += fmt.Sprintf("'%s'", *m.cursor)
	} else {
		cursorInfo += "nil"
	}
	cursorInfo += " | NextCursor: "
	if m.nextCursor != nil {
		cursorInfo += fmt.Sprintf("'%s'", *m.nextCursor)
	} else {
		cursorInfo += "nil"
	}
	content.WriteString(styles.MutedColor.Render(cursorInfo))

	// Help
	content.WriteString("\n\n")
	helpText := "↑/↓: navigate | Enter: view details | e: filter event | s: filter severity | c: clear | n/p: next/prev | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *AuditModel) renderAuditRow(record client.AuditRecord, selected bool) string {
	timestamp := record.Timestamp.Format("2006-01-02 15:04:05")

	eventType := record.EventType
	if len(eventType) > 20 {
		eventType = eventType[:17] + "..."
	}

	// Get signer or request info
	signerInfo := ""
	if record.SignerAddress != nil {
		signerInfo = *record.SignerAddress
		if len(signerInfo) > 42 {
			signerInfo = signerInfo[:39] + "..."
		}
	} else if record.SignRequestID != nil {
		signerInfo = *record.SignRequestID
		if len(signerInfo) > 42 {
			signerInfo = signerInfo[:39] + "..."
		}
	}

	// Get brief details
	details := ""
	if record.ErrorMessage != "" {
		details = record.ErrorMessage
	} else if record.RequestPath != "" {
		details = fmt.Sprintf("%s %s", record.RequestMethod, record.RequestPath)
	}
	if len(details) > 24 {
		details = details[:21] + "..."
	}

	row := fmt.Sprintf("%-20s  %-10s  %-20s  %-42s  %-24s",
		timestamp,
		record.Severity,
		eventType,
		signerInfo,
		details,
	)

	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}

	// Color severity
	severityStyle := styles.GetSeverityStyle(record.Severity)
	severityPart := severityStyle.Render(fmt.Sprintf("%-10s", record.Severity))

	row = fmt.Sprintf("%-20s  %s  %-20s  %-42s  %-24s",
		timestamp,
		severityPart,
		eventType,
		signerInfo,
		details,
	)

	return styles.TableRowStyle.Render(row)
}

func (m *AuditModel) renderDetail() string {
	if len(m.records) == 0 || m.selectedIdx >= len(m.records) {
		return "No record selected"
	}

	record := m.records[m.selectedIdx]

	var content strings.Builder

	content.WriteString(styles.TitleStyle.Render("Audit Record Details"))
	content.WriteString("\n\n")

	// Basic info
	info := []struct {
		key   string
		value string
	}{
		{"ID", string(record.ID)},
		{"Event Type", record.EventType},
		{"Severity", record.Severity},
		{"Timestamp", record.Timestamp.Format("2006-01-02 15:04:05")},
		{"API Key ID", record.APIKeyID},
		{"Actor Address", record.ActorAddress},
		{"Request Method", record.RequestMethod},
		{"Request Path", record.RequestPath},
	}

	if record.SignRequestID != nil {
		info = append(info, struct{ key, value string }{"Sign Request ID", *record.SignRequestID})
	}
	if record.SignerAddress != nil {
		info = append(info, struct{ key, value string }{"Signer Address", *record.SignerAddress})
	}
	if record.ChainType != nil {
		info = append(info, struct{ key, value string }{"Chain Type", *record.ChainType})
	}
	if record.ChainID != nil {
		info = append(info, struct{ key, value string }{"Chain ID", *record.ChainID})
	}
	if record.RuleID != nil {
		info = append(info, struct{ key, value string }{"Rule ID", *record.RuleID})
	}

	for _, item := range info {
		if item.value == "" {
			continue
		}
		keyStr := styles.InfoKeyStyle.Render(item.key + ":")
		valueStr := item.value
		if item.key == "Severity" {
			valueStr = styles.GetSeverityStyle(item.value).Render(item.value)
		}
		content.WriteString(fmt.Sprintf("%s %s\n", keyStr, valueStr))
	}

	// Error message
	if record.ErrorMessage != "" {
		content.WriteString("\n")
		content.WriteString(styles.SubtitleStyle.Render("Error Message"))
		content.WriteString("\n")
		content.WriteString(styles.ErrorStyle.Render(record.ErrorMessage))
		content.WriteString("\n")
	}

	// Details
	if record.Details != nil {
		content.WriteString("\n")
		content.WriteString(styles.SubtitleStyle.Render("Details"))
		content.WriteString("\n")
		detailsJSON, err := json.MarshalIndent(record.Details, "", "  ")
		if err == nil && string(detailsJSON) != "null" {
			content.WriteString(styles.MutedColor.Render(string(detailsJSON)))
		} else {
			content.WriteString(styles.MutedColor.Render("No additional details"))
		}
		content.WriteString("\n")
	}

	// Split content into lines for scrolling
	lines := strings.Split(content.String(), "\n")
	totalLines := len(lines)

	// Calculate visible area (leave room for help text and border)
	visibleHeight := m.height - 6
	if visibleHeight < 5 {
		visibleHeight = 5
	}

	// Clamp scroll position
	maxScroll := totalLines - visibleHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.detailScroll > maxScroll {
		m.detailScroll = maxScroll
	}

	// Get visible lines
	start := m.detailScroll
	end := start + visibleHeight
	if end > totalLines {
		end = totalLines
	}
	visibleLines := lines[start:end]

	// Build final output
	var output strings.Builder
	output.WriteString(strings.Join(visibleLines, "\n"))

	// Add scroll indicator
	output.WriteString("\n\n")
	scrollInfo := fmt.Sprintf("Line %d-%d of %d", start+1, end, totalLines)
	if m.detailScroll > 0 {
		scrollInfo = "^ " + scrollInfo
	}
	if m.detailScroll < maxScroll {
		scrollInfo = scrollInfo + " v"
	}
	output.WriteString(styles.MutedColor.Render(scrollInfo))

	// Help
	output.WriteString("\n")
	helpText := "Esc: back | j/k: scroll | PgUp/PgDn: fast scroll | g: top"
	output.WriteString(styles.HelpStyle.Render(helpText))

	return styles.BoxStyle.Width(m.width - 4).Render(output.String())
}
