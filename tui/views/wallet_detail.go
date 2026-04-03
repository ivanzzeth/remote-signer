package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

type WalletDetailModel struct {
	walletsSvc    evm.WalletAPI
	signersSvc    evm.SignerAPI
	ctx           context.Context
	spinner       spinner.Model
	loading       bool
	err           error
	wallet        *evm.Wallet
	walletID      string
	members       []evm.WalletMember
	selectedIdx   int
	goBack        bool
	showAddPicker bool
	addCandidates []evm.Signer
	addSelected   int
	showRemove    bool
	actionMessage string
}

type walletDetailDataMsg struct {
	members []evm.WalletMember
	err     error
}

type walletDetailAddCandidatesMsg struct {
	signers []evm.Signer
	err     error
}

func NewWalletDetailModel(c *client.Client, ctx context.Context) (*WalletDetailModel, error) {
	if c == nil || c.EVM == nil || c.EVM.Wallets == nil || c.EVM.Signers == nil {
		return nil, fmt.Errorf("wallet and signer APIs are required")
	}
	return newWalletDetailModelFromService(c.EVM.Wallets, c.EVM.Signers, ctx)
}

func newWalletDetailModelFromService(wallets evm.WalletAPI, signers evm.SignerAPI, ctx context.Context) (*WalletDetailModel, error) {
	if wallets == nil || signers == nil {
		return nil, fmt.Errorf("wallet and signer APIs are required")
	}
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle
	return &WalletDetailModel{walletsSvc: wallets, signersSvc: signers, ctx: ctx, spinner: s}, nil
}

func (m *WalletDetailModel) Init() tea.Cmd { return nil }
func (m *WalletDetailModel) SetSize(width, height int) {}
func (m *WalletDetailModel) ShouldGoBack() bool { return m.goBack }
func (m *WalletDetailModel) ResetGoBack() { m.goBack = false }
func (m *WalletDetailModel) IsCapturingInput() bool { return m.showAddPicker || m.showRemove }
func (m *WalletDetailModel) ShouldOpenMember() bool { return false }
func (m *WalletDetailModel) GetOpenMemberWalletID() string { return "" }

func (m *WalletDetailModel) LoadWallet(w evm.Wallet) tea.Cmd {
	m.wallet = &w
	m.walletID = w.ID
	m.loading = true
	m.err = nil
	m.selectedIdx = 0
	return tea.Batch(m.spinner.Tick, m.loadMembers())
}

func (m *WalletDetailModel) loadMembers() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.walletsSvc.ListMembers(m.ctx, m.walletID)
		if err != nil {
			return walletDetailDataMsg{err: err}
		}
		return walletDetailDataMsg{members: resp.Members}
	}
}

func (m *WalletDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case walletDetailDataMsg:
		m.loading = false
		m.err = msg.err
		if msg.err == nil {
			m.members = msg.members
		}
	case walletDetailAddCandidatesMsg:
		m.loading = false
		m.err = msg.err
		if msg.err == nil {
			m.addCandidates = msg.signers
			m.addSelected = 0
			m.showAddPicker = true
		}
	case spinner.TickMsg:
		if m.loading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	case tea.KeyMsg:
		if m.showAddPicker {
			switch msg.String() {
			case "esc":
				m.showAddPicker = false
				return m, nil
			case "up", "k":
				if m.addSelected > 0 {
					m.addSelected--
				}
				return m, nil
			case "down", "j":
				if m.addSelected < len(m.addCandidates)-1 {
					m.addSelected++
				}
				return m, nil
			case "enter":
				m.showAddPicker = false
				if len(m.addCandidates) == 0 || m.addSelected >= len(m.addCandidates) {
					m.actionMessage = styles.ErrorStyle.Render("No signer selected")
					return m, nil
				}
				addr := strings.TrimSpace(m.addCandidates[m.addSelected].Address)
				m.loading = true
				return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
					_, err := m.walletsSvc.AddMember(m.ctx, m.walletID, &evm.AddWalletMemberRequest{SignerAddress: addr})
					if err != nil {
						return walletDetailDataMsg{err: err}
					}
					m.actionMessage = styles.SuccessStyle.Render("Member added")
					return m.loadMembers()()
				})
			}
		}
		if m.showRemove {
			switch msg.String() {
			case "y", "Y":
				m.showRemove = false
				if m.selectedIdx < len(m.members) {
					addr := m.members[m.selectedIdx].SignerAddress
					m.loading = true
					return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
						err := m.walletsSvc.RemoveMember(m.ctx, m.walletID, addr)
						if err != nil {
							return walletDetailDataMsg{err: err}
						}
						m.actionMessage = styles.SuccessStyle.Render("Member removed")
						return m.loadMembers()()
					})
				}
			case "n", "N", "esc":
				m.showRemove = false
			}
			return m, nil
		}
		switch msg.String() {
		case "esc", "q", "backspace":
			m.goBack = true
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "down", "j":
			if m.selectedIdx < len(m.members)-1 {
				m.selectedIdx++
			}
		case "a":
			m.loading = true
			return m, tea.Batch(m.spinner.Tick, m.loadAddCandidates())
		case "d":
			if len(m.members) > 0 {
				m.showRemove = true
			}
		case "D":
			m.loading = true
			return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
				if err := m.walletsSvc.Delete(m.ctx, m.walletID); err != nil {
					return walletDetailDataMsg{err: err}
				}
				m.goBack = true
				return walletDetailDataMsg{}
			})
		case "r":
			m.loading = true
			return m, tea.Batch(m.spinner.Tick, m.loadMembers())
		}
	}
	return m, nil
}

func (m *WalletDetailModel) View() string {
	if m.loading {
		return "\n  " + m.spinner.View() + " Loading wallet details..."
	}
	if m.err != nil {
		return fmt.Sprintf("\n  Error: %v", m.err)
	}
	if m.showAddPicker {
		var b strings.Builder
		b.WriteString("Add Signer Member\n\n")
		if len(m.addCandidates) == 0 {
			b.WriteString("  No available signers\n\n")
			b.WriteString("  esc: cancel")
			return b.String()
		}
		for i, s := range m.addCandidates {
			prefix := "  "
			if i == m.addSelected {
				prefix = "➜ "
			}
			b.WriteString(fmt.Sprintf("%s%s\n", prefix, s.Address))
		}
		b.WriteString("\n  ↑/↓: select • enter: add • esc: cancel")
		return b.String()
	}
	if m.showRemove {
		return "Remove selected member?\n\n  y: confirm • n: cancel"
	}
	var b strings.Builder
	b.WriteString(styles.TitleStyle.Render("Wallet Detail") + "\n\n")
	b.WriteString(fmt.Sprintf("Wallet ID: %s\n\n", m.walletID))
	if m.actionMessage != "" {
		b.WriteString(m.actionMessage + "\n\n")
	}
	for i, member := range m.members {
		prefix := "  "
		if i == m.selectedIdx {
			prefix = "➜ "
		}
		b.WriteString(fmt.Sprintf("%s%s\n", prefix, member.SignerAddress))
	}
	b.WriteString("\n")
	b.WriteString(styles.HelpStyle.Render("↑/↓: select • a: add • d: remove • D: delete wallet • r: refresh • esc: back"))
	return b.String()
}

func (m *WalletDetailModel) loadAddCandidates() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.signersSvc.List(m.ctx, &evm.ListSignersFilter{Limit: 1000})
		if err != nil {
			return walletDetailAddCandidatesMsg{err: err}
		}
		memberSet := map[string]struct{}{}
		for _, member := range m.members {
			memberSet[strings.ToLower(member.SignerAddress)] = struct{}{}
		}
		candidates := make([]evm.Signer, 0, len(resp.Signers))
		for _, signer := range resp.Signers {
			if _, ok := memberSet[strings.ToLower(signer.Address)]; ok {
				continue
			}
			candidates = append(candidates, signer)
		}
		return walletDetailAddCandidatesMsg{signers: candidates}
	}
}
