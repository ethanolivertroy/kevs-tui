package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Colors (theme-aware - updated by theme.go)
var (
	PrimaryColor    = lipgloss.Color("#7D56F4")
	SecondaryColor  = lipgloss.Color("#04B575")
	WarningColor    = lipgloss.Color("#FFCC00")
	ErrorColor      = lipgloss.Color("#FF5F56")
	SubtleColor     = lipgloss.Color("#626262")
	RansomwareColor = lipgloss.Color("#FF0000")
	OverdueColor    = lipgloss.Color("#FF5F56")
	EPSSHighColor   = lipgloss.Color("#FF5F56")
	EPSSMedColor    = lipgloss.Color("#FFCC00")
	EPSSLowColor    = lipgloss.Color("#04B575")
	URLColor        = lipgloss.Color("#00BFFF")
	CWEColor        = lipgloss.Color("#DDA0DD")
	// CVSS severity colors
	CriticalColor     = lipgloss.Color("#9B0000")
	HighColor         = lipgloss.Color("#FF5F56")
	MediumColor       = lipgloss.Color("#FFCC00")
	LowColor          = lipgloss.Color("#04B575")
	CVSSCriticalColor = lipgloss.Color("#9B0000")
	CVSSHighColor     = lipgloss.Color("#FF5F56")
	CVSSMediumColor   = lipgloss.Color("#FFCC00")
	CVSSLowColor      = lipgloss.Color("#04B575")
)

// Styles
var (
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(PrimaryColor).
			Padding(0, 1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(SubtleColor)

	// Detail view styles
	LabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(PrimaryColor).
			Width(18)

	ValueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF"))

	URLStyle = lipgloss.NewStyle().
			Foreground(SecondaryColor).
			Underline(true)

	DescriptionStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#CCCCCC")).
				Width(80)

	// Badge styles
	RansomwareBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(RansomwareColor).
			Padding(0, 1)

	SafeBadge = lipgloss.NewStyle().
			Foreground(SubtleColor).
			Padding(0, 1)

	CVEBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(PrimaryColor).
			Padding(0, 1)

	CWEStyle = lipgloss.NewStyle().
			Foreground(WarningColor)

	// List item styles
	SelectedItemStyle = lipgloss.NewStyle().
				BorderLeft(true).
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(PrimaryColor).
				PaddingLeft(1)

	NormalItemStyle = lipgloss.NewStyle().
			PaddingLeft(2)

	DimmedItemStyle = lipgloss.NewStyle().
			Foreground(SubtleColor).
			PaddingLeft(2)
)

// RansomwareBadgeText returns a formatted ransomware badge
func RansomwareBadgeText(isRansomware bool) string {
	if isRansomware {
		return RansomwareBadge.Render("RANSOMWARE")
	}
	return SafeBadge.Render("Unknown")
}

// OverdueBadge style
var OverdueBadge = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#FFFFFF")).
	Background(OverdueColor).
	Padding(0, 1)

// DueSoonBadge style
var DueSoonBadge = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#000000")).
	Background(WarningColor).
	Padding(0, 1)

// EPSSBadge returns a colored EPSS badge based on score
func EPSSBadge(score float64) string {
	if score == 0 {
		return ""
	}
	pct := score * 100
	var style lipgloss.Style
	if pct >= 50 {
		style = lipgloss.NewStyle().Foreground(EPSSHighColor).Bold(true)
	} else if pct >= 10 {
		style = lipgloss.NewStyle().Foreground(EPSSMedColor)
	} else {
		style = lipgloss.NewStyle().Foreground(EPSSLowColor)
	}
	return style.Render(fmt.Sprintf("%.0f%%", pct))
}

// EPSSBar returns a visual bar representing EPSS score
func EPSSBar(score float64, width int) string {
	if score == 0 || width <= 0 {
		return ""
	}
	filled := int(score * float64(width))
	if filled < 1 && score > 0 {
		filled = 1
	}
	empty := width - filled

	var color lipgloss.Color
	pct := score * 100
	if pct >= 50 {
		color = EPSSHighColor
	} else if pct >= 10 {
		color = EPSSMedColor
	} else {
		color = EPSSLowColor
	}

	filledStyle := lipgloss.NewStyle().Foreground(color)
	emptyStyle := lipgloss.NewStyle().Foreground(SubtleColor)

	return filledStyle.Render(strings.Repeat("█", filled)) +
		emptyStyle.Render(strings.Repeat("░", empty))
}

// DueDateBadge returns a colored badge based on due date status
func DueDateBadge(daysUntil int, isOverdue bool) string {
	if isOverdue {
		return OverdueBadge.Render(fmt.Sprintf("OVERDUE %dd", -daysUntil))
	}
	if daysUntil <= 7 {
		return DueSoonBadge.Render(fmt.Sprintf("%dd left", daysUntil))
	}
	return lipgloss.NewStyle().Foreground(SubtleColor).Render(fmt.Sprintf("%dd left", daysUntil))
}

// StatsStyle for statistics header
var StatsStyle = lipgloss.NewStyle().
	Foreground(SubtleColor).
	Padding(0, 1)

// StatHighlight for important stats
var StatHighlight = lipgloss.NewStyle().
	Foreground(PrimaryColor).
	Bold(true)

// CVSSBadge returns a colored CVSS score badge based on severity
func CVSSBadge(score float64, severity string) string {
	var bgColor lipgloss.Color
	switch severity {
	case "CRITICAL":
		bgColor = CVSSCriticalColor
	case "HIGH":
		bgColor = CVSSHighColor
	case "MEDIUM":
		bgColor = CVSSMediumColor
	case "LOW":
		bgColor = CVSSLowColor
	default:
		bgColor = SubtleColor
	}

	style := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(bgColor).
		Padding(0, 1)

	return style.Render(fmt.Sprintf("CVSS %.1f %s", score, severity))
}
