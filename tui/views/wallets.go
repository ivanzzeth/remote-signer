package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

type WalletsModel struct {
	walletsSvc   evm.WalletAPI
	ctx          context.Context
	spinner      spinner.Model
	loading      bool
	err          error
	wallets      []evm.Wallet
	total        int
	hasMore      bool
	selectedIdx  int
	offset       int
	limit        int
	goDetail     bool
	selectedID   string
	showCreate   bool
	createInput  textinput.Model
	showDelete   bool
	actionResult string
}

type walletsDataMsg struct {
	wallets []evm.Wallet
	total   int
	hasMore bool
	err     error
}

type walletsActionMsg struct {
	action string
	err    error
}

func NewWalletsModel(c *client.Client, ctx context.Context) (*WalletsModel, error) {
	if c == nil || c.EVM == nil || c.EVM.Wallets == nil {
		return nil, fmt.Errorf("wallet API is required")
	}
	return newWalletsModelFromService(c.EVM.Wallets, ctx)
}

func newWalletsModelFromService(wallets evm.WalletAPI, ctx context.Context) (*WalletsModel, error) {
	if wallets == nil {
		return nil, fmt.Errorf("wallet API is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle
	in := textinput.New()
	in.Placeholder = "Wallet name"
	in.Width = 40
	return &WalletsModel{
		walletsSvc:  wallets,
		ctx:         ctx,
		spinner:     s,
		loading:     true,
		limit:       20,
		createInput: in,
	}, nil
}

func (m *WalletsModel) Init() tea.Cmd { return tea.Batch(m.spinner.Tick, m.fetchWallets) }

func (m *WalletsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.showCreate {
			return m.updateCreate(msg)
		}
		if m.showDelete {
			switch msg.String() {
			case "y", "Y":
				m.showDelete = false
				if m.selectedIdx < len(m.wallets) {
					m.loading = true
					id := m.wallets[m.selectedIdx].ID
					return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
						return walletsActionMsg{action: "delete", err: m.walletsSvc.Delete(m.ctx, id)}
					})
				}
			case "n", "N", "esc":
				m.showDelete = false
			}
			return m, nil
		}
		switch msg.String() {
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "down", "j":
			if m.selectedIdx < len(m.wallets)-1 {
				m.selectedIdx++
			}
		case "enter":
			if m.selectedIdx < len(m.wallets) {
				m.goDetail = true
				m.selectedID = m.wallets[m.selectedIdx].ID
			}
		case "a", "+":
			m.showCreate = true
			m.createInput.SetValue("")
			m.createInput.Focus()
			return m, textinput.Blink
		case "D":
			if len(m.wallets) > 0 {
				m.showDelete = true
			}
		case "r":
			m.loading = true
			return m, tea.Batch(m.spinner.Tick, m.fetchWallets)
		}
	case walletsDataMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.wallets = msg.wallets
			m.total = msg.total
			m.hasMore = msg.hasMore
			m.err = nil
		}
	case walletsActionMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
			m.actionResult = styles.ErrorStyle.Render(fmt.Sprintf("Wallet %s failed: %v", msg.action, msg.err))
			return m, nil
		}
		m.err = nil
		if msg.action == "create" {
			m.actionResult = styles.SuccessStyle.Render("Wallet created")
		} else if msg.action == "delete" {
			m.actionResult = styles.SuccessStyle.Render("Wallet deleted")
		}
		m.loading = true
		return m, tea.Batch(m.spinner.Tick, m.fetchWallets)
	case spinner.TickMsg:
		if m.loading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m *WalletsModel) updateCreate(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.showCreate = false
		return m, nil
	case "enter":
		name := strings.TrimSpace(m.createInput.Value())
		m.showCreate = false
		if name == "" {
			m.actionResult = styles.ErrorStyle.Render("Wallet name required")
			return m, nil
		}
		m.loading = true
		return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
			_, err := m.walletsSvc.Create(m.ctx, &evm.CreateWalletRequest{Name: name})
			return walletsActionMsg{action: "create", err: err}
		})
	}
	var cmd tea.Cmd
	m.createInput, cmd = m.createInput.Update(msg)
	return m, cmd
}

func (m *WalletsModel) View() string {
	if m.loading {
		return "\n  " + m.spinner.View() + " Loading wallets..."
	}
	if m.err != nil {
		return fmt.Sprintf("\n  Error: %v", m.err)
	}
	if m.showCreate {
		return "New Wallet\n\n  " + m.createInput.View() + "\n\n  enter: create • esc: cancel"
	}
	if m.showDelete {
		return "Delete wallet?\n\n  y: confirm • n: cancel"
	}
	var b strings.Builder
	b.WriteString(styles.TitleStyle.Render("Wallets") + "\n\n")
	if m.actionResult != "" {
		b.WriteString(m.actionResult + "\n\n")
	}
	b.WriteString(styles.TableHeaderStyle.Render(fmt.Sprintf("%-2s  %-18s  %-24s  %-16s  %-16s  %-16s", "", "Name", "Description", "Owner", "Created", "Updated")))
	b.WriteString("\n")
	for i, w := range m.wallets {
		prefix := "  "
		if i == m.selectedIdx {
			prefix = "➜ "
		}
		desc := w.Description
		if desc == "" {
			desc = "-"
		}
		if len(desc) > 24 {
			desc = desc[:21] + "..."
		}
		owner := "-"
		if w.OwnerID != "" {
			owner = w.OwnerID
		}
		row := fmt.Sprintf("%-2s  %-18s  %-24s  %-16s  %-16s  %-16s",
			prefix,
			truncate(w.Name, 18),
			desc,
			truncate(owner, 16),
			w.CreatedAt.Format("2006-01-02 15:04"),
			w.UpdatedAt.Format("2006-01-02 15:04"),
		)
		if i == m.selectedIdx {
			b.WriteString(styles.TableSelectedRowStyle.Render(row))
		} else {
			b.WriteString(styles.TableRowStyle.Render(row))
		}
		b.WriteString("\n")
	}
	pageInfo := fmt.Sprintf("Total: %d", m.total)
	if m.hasMore {
		pageInfo += " (more available)"
	}
	b.WriteString("\n" + styles.MutedColor.Render(pageInfo) + "\n")
	b.WriteString(styles.HelpStyle.Render("↑/↓: select • enter: detail • a: create • D: delete • r: refresh • q: quit"))
	return b.String()
}

func (m *WalletsModel) fetchWallets() tea.Msg {
	resp, err := m.walletsSvc.List(m.ctx, &evm.ListWalletsFilter{Offset: m.offset, Limit: m.limit})
	if err != nil {
		return walletsDataMsg{err: err}
	}
	return walletsDataMsg{wallets: resp.Wallets, total: resp.Total, hasMore: resp.HasMore}
}

func (m *WalletsModel) SetSize(width, height int) {}
func (m *WalletsModel) ShouldShowDetail() bool    { return m.goDetail }
func (m *WalletsModel) SelectedWallet() string    { return m.selectedID }
func (m *WalletsModel) ClearDetailFlag()          { m.goDetail, m.selectedID = false, "" }
func (m *WalletsModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(m.spinner.Tick, m.fetchWallets)
}
func (m *WalletsModel) IsCapturingInput() bool { return m.showCreate || m.showDelete }
func (m *WalletsModel) GetSelectedWallet() evm.Wallet {
	for _, w := range m.wallets {
		if w.ID == m.selectedID {
			return w
		}
	}
	return evm.Wallet{ID: m.selectedID}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
