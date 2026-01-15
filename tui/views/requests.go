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
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// RequestsModel represents the requests list view
type RequestsModel struct {
	client       client.ClientInterface
	ctx          context.Context
	width        int
	height       int
	spinner      spinner.Model
	loading      bool
	err          error
	requests     []client.RequestStatus
	total        int
	selectedIdx  int
	limit        int
	statusFilter string
	showFilter   bool
	filterInput  textinput.Model
	// Cursor-based pagination
	cursor        *string       // Cursor used to fetch current page
	cursorID      *string       // CursorID used to fetch current page
	nextCursor    *string       // Cursor for next page (from response)
	nextCursorID  *string       // CursorID for next page (from response)
	cursorHistory []cursorState // History for previous page navigation
	hasMore       bool
}

// cursorState stores cursor position for pagination history
type cursorState struct {
	cursor   *string
	cursorID *string
}

// RequestsDataMsg is sent when requests data is loaded
type RequestsDataMsg struct {
	Requests     []client.RequestStatus
	Total        int
	NextCursor   *string
	NextCursorID *string
	HasMore      bool
	Err          error
}

// NewRequestsModel creates a new requests model
func NewRequestsModel(c client.ClientInterface, ctx context.Context) (*RequestsModel, error) {
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
	ti.Placeholder = "Status filter (pending, authorizing, completed, rejected, failed)"
	ti.Width = 60

	return &RequestsModel{
		client:      c,
		ctx:         ctx,
		spinner:     s,
		loading:     true,
		limit:       20,
		filterInput: ti,
	}, nil
}

// Init initializes the requests view
func (m *RequestsModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// SetSize sets the view size
func (m *RequestsModel) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Refresh refreshes the requests data
func (m *RequestsModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadData(),
	)
}

// GetSelectedRequestID returns the ID of the selected request
func (m *RequestsModel) GetSelectedRequestID() string {
	if len(m.requests) == 0 || m.selectedIdx >= len(m.requests) {
		return ""
	}
	return m.requests[m.selectedIdx].ID
}

// resetPagination resets cursor state to first page
func (m *RequestsModel) resetPagination() {
	m.cursor = nil
	m.cursorID = nil
	m.nextCursor = nil
	m.nextCursorID = nil
	m.cursorHistory = nil
	m.selectedIdx = 0
	m.hasMore = false
}

func (m *RequestsModel) loadData() tea.Cmd {
	return func() tea.Msg {
		filter := &client.ListRequestsFilter{
			Status:   m.statusFilter,
			Limit:    m.limit,
			Cursor:   m.cursor,
			CursorID: m.cursorID,
		}
		resp, err := m.client.ListRequests(m.ctx, filter)
		if err != nil {
			return RequestsDataMsg{Err: err}
		}
		return RequestsDataMsg{
			Requests:     resp.Requests,
			Total:        resp.Total,
			NextCursor:   resp.NextCursor,
			NextCursorID: resp.NextCursorID,
			HasMore:      resp.HasMore,
			Err:          nil,
		}
	}
}

// Update handles messages
func (m *RequestsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case RequestsDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
		} else {
			m.requests = msg.Requests
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
		// If filter input is active
		if m.showFilter {
			switch msg.String() {
			case "enter":
				m.statusFilter = m.filterInput.Value()
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
		case "f":
			m.showFilter = true
			m.filterInput.Focus()
			return m, textinput.Blink
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.selectedIdx < len(m.requests)-1 {
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
			if m.selectedIdx >= len(m.requests) {
				m.selectedIdx = len(m.requests) - 1
			}
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			return m, nil
		case "home", "g":
			m.selectedIdx = 0
			return m, nil
		case "end", "G":
			if len(m.requests) > 0 {
				m.selectedIdx = len(m.requests) - 1
			}
			return m, nil
		case "n":
			// Next page
			if m.hasMore && m.nextCursor != nil {
				// Save current cursor to history for going back
				m.cursorHistory = append(m.cursorHistory, cursorState{
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
			// Clear filter
			m.statusFilter = ""
			m.filterInput.SetValue("")
			m.resetPagination()
			return m, m.Refresh()
		}
	}

	return m, nil
}

// View renders the requests view
func (m *RequestsModel) View() string {
	if m.showFilter {
		return m.renderFilterInput()
	}

	if m.loading {
		return m.renderLoading()
	}

	if m.err != nil {
		return m.renderError()
	}

	return m.renderRequests()
}

func (m *RequestsModel) renderLoading() string {
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		fmt.Sprintf("%s Loading requests...", m.spinner.View()),
	)
}

func (m *RequestsModel) renderError() string {
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

func (m *RequestsModel) renderFilterInput() string {
	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Filter Requests"))
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

func (m *RequestsModel) renderRequests() string {
	var content strings.Builder

	// Header
	header := styles.SubtitleStyle.Render("Sign Requests")
	if m.statusFilter != "" {
		header += styles.MutedColor.Render(fmt.Sprintf(" (filtered: %s)", m.statusFilter))
	}
	content.WriteString(header)
	content.WriteString("\n\n")

	// Table header
	headerRow := fmt.Sprintf("%-36s  %-12s  %-12s  %-42s  %-20s",
		"ID", "Status", "Sign Type", "Signer", "Created At")
	content.WriteString(styles.TableHeaderStyle.Render(headerRow))
	content.WriteString("\n")

	// Rows
	if len(m.requests) == 0 {
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  No requests found"))
	} else {
		for i, req := range m.requests {
			row := m.renderRequestRow(req, i == m.selectedIdx)
			content.WriteString(row)
			content.WriteString("\n")
		}
	}

	// Pagination info
	content.WriteString("\n")
	pageNum := len(m.cursorHistory) + 1
	pagination := fmt.Sprintf("Page %d | Showing %d items | Total: %d", pageNum, len(m.requests), m.total)
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
	helpText := "↑/↓: navigate | Enter: view details | f: filter | c: clear filter | n/p: next/prev page | r: refresh"
	content.WriteString(styles.HelpStyle.Render(helpText))

	return content.String()
}

func (m *RequestsModel) renderRequestRow(req client.RequestStatus, selected bool) string {
	// Truncate ID for display
	id := req.ID
	if len(id) > 36 {
		id = id[:33] + "..."
	}

	// Format timestamp
	createdAt := req.CreatedAt.Format("2006-01-02 15:04:05")

	// Truncate signer address
	signer := req.SignerAddress
	if len(signer) > 42 {
		signer = signer[:39] + "..."
	}

	row := fmt.Sprintf("%-36s  %-12s  %-12s  %-42s  %-20s",
		id,
		req.Status,
		req.SignType,
		signer,
		createdAt,
	)

	if selected {
		return styles.TableSelectedRowStyle.Render(row)
	}

	// Color status
	statusStyle := styles.GetStatusStyle(req.Status)
	statusPart := statusStyle.Render(fmt.Sprintf("%-12s", req.Status))

	row = fmt.Sprintf("%-36s  %s  %-12s  %-42s  %-20s",
		id,
		statusPart,
		req.SignType,
		signer,
		createdAt,
	)

	return styles.TableRowStyle.Render(row)
}
