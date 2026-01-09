package styles

import "github.com/charmbracelet/lipgloss"

// Color constants
const (
	primaryColorHex   = "#7C3AED"
	secondaryColorHex = "#06B6D4"
	successColorHex   = "#10B981"
	warningColorHex   = "#F59E0B"
	errorColorHex     = "#EF4444"
	textColorHex      = "#E5E7EB"
	mutedColorHex     = "#6B7280"
	borderColorHex    = "#374151"
	bgColorHex        = "#111827"
	bgLightColorHex   = "#1F2937"
)

var (
	// Colors (for direct use as colors)
	PrimaryColor   = lipgloss.Color(primaryColorHex)
	SecondaryColor = lipgloss.Color(secondaryColorHex)
	SuccessColor   = lipgloss.Color(successColorHex)
	WarningColor   = lipgloss.Color(warningColorHex)
	ErrorColor     = lipgloss.Color(errorColorHex)
	TextColor      = lipgloss.Color(textColorHex)
	MutedColorVal  = lipgloss.Color(mutedColorHex)
	BorderColor    = lipgloss.Color(borderColorHex)
	BgColor        = lipgloss.Color(bgColorHex)
	BgLightColor   = lipgloss.Color(bgLightColorHex)

	// MutedColor as a style for rendering
	MutedColor = lipgloss.NewStyle().Foreground(MutedColorVal)

	// Base styles
	BaseStyle = lipgloss.NewStyle().
			Foreground(TextColor).
			Background(BgColor)

	// Title styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(PrimaryColor).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(SecondaryColor).
			MarginBottom(1)

	// Tab styles
	TabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Foreground(MutedColorVal)

	ActiveTabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Foreground(PrimaryColor).
			Bold(true).
			Underline(true)

	// Status styles
	StatusPending = lipgloss.NewStyle().
			Foreground(WarningColor).
			Bold(true)

	StatusAuthorizing = lipgloss.NewStyle().
				Foreground(SecondaryColor).
				Bold(true)

	StatusSigning = lipgloss.NewStyle().
			Foreground(SecondaryColor).
			Bold(true)

	StatusCompleted = lipgloss.NewStyle().
			Foreground(SuccessColor).
			Bold(true)

	StatusRejected = lipgloss.NewStyle().
			Foreground(ErrorColor).
			Bold(true)

	StatusFailed = lipgloss.NewStyle().
			Foreground(ErrorColor).
			Bold(true)

	// Box styles
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(BorderColor).
			Padding(1, 2)

	SelectedBoxStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(PrimaryColor).
				Padding(1, 2)

	// Table styles
	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(PrimaryColor).
				BorderBottom(true).
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(BorderColor)

	TableRowStyle = lipgloss.NewStyle().
			Foreground(TextColor)

	TableSelectedRowStyle = lipgloss.NewStyle().
				Foreground(BgColor).
				Background(PrimaryColor).
				Bold(true)

	// Button styles
	ButtonStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Background(BgLightColor).
			Foreground(TextColor).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(BorderColor)

	ButtonActiveStyle = lipgloss.NewStyle().
				Padding(0, 2).
				Background(PrimaryColor).
				Foreground(BgColor).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(PrimaryColor).
				Bold(true)

	ButtonSuccessStyle = lipgloss.NewStyle().
				Padding(0, 2).
				Background(SuccessColor).
				Foreground(BgColor).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(SuccessColor).
				Bold(true)

	ButtonDangerStyle = lipgloss.NewStyle().
				Padding(0, 2).
				Background(ErrorColor).
				Foreground(BgColor).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ErrorColor).
				Bold(true)

	// Help styles
	HelpStyle = lipgloss.NewStyle().
			Foreground(MutedColorVal).
			MarginTop(1)

	// Info styles
	InfoKeyStyle = lipgloss.NewStyle().
			Foreground(MutedColorVal).
			Width(20)

	InfoValueStyle = lipgloss.NewStyle().
			Foreground(TextColor)

	// Badge styles
	BadgeStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Background(BgLightColor).
			Foreground(TextColor)

	// Severity styles
	SeverityInfo = lipgloss.NewStyle().
			Foreground(SecondaryColor)

	SeverityWarning = lipgloss.NewStyle().
			Foreground(WarningColor)

	SeverityCritical = lipgloss.NewStyle().
				Foreground(ErrorColor).
				Bold(true)

	// Spinner style
	SpinnerStyle = lipgloss.NewStyle().
			Foreground(PrimaryColor)

	// Error message style
	ErrorStyle = lipgloss.NewStyle().
			Foreground(ErrorColor).
			Bold(true)

	// Success message style
	SuccessStyle = lipgloss.NewStyle().
			Foreground(SuccessColor).
			Bold(true)
)

// GetStatusStyle returns the appropriate style for a given status
func GetStatusStyle(status string) lipgloss.Style {
	switch status {
	case "pending":
		return StatusPending
	case "authorizing":
		return StatusAuthorizing
	case "signing":
		return StatusSigning
	case "completed":
		return StatusCompleted
	case "rejected":
		return StatusRejected
	case "failed":
		return StatusFailed
	default:
		return lipgloss.NewStyle().Foreground(MutedColorVal)
	}
}

// GetSeverityStyle returns the appropriate style for a given severity
func GetSeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "info":
		return SeverityInfo
	case "warning":
		return SeverityWarning
	case "critical":
		return SeverityCritical
	default:
		return lipgloss.NewStyle().Foreground(TextColor)
	}
}
