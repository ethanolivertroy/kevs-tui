package tui

import "github.com/charmbracelet/lipgloss"

// ThemeName identifies a color theme
type ThemeName string

const (
	ThemeDefault    ThemeName = "default"
	ThemeDracula    ThemeName = "dracula"
	ThemeCatppuccin ThemeName = "catppuccin"
	ThemeNord       ThemeName = "nord"
)

// Theme holds color definitions for the TUI
type Theme struct {
	Name       ThemeName
	Primary    lipgloss.Color
	Secondary  lipgloss.Color
	Subtle     lipgloss.Color
	Overdue    lipgloss.Color
	Critical   lipgloss.Color
	High       lipgloss.Color
	Medium     lipgloss.Color
	Low        lipgloss.Color
	Ransomware lipgloss.Color
	URL        lipgloss.Color
	CWE        lipgloss.Color
	Background lipgloss.Color
	Foreground lipgloss.Color
}

// Themes available in the application
var Themes = map[ThemeName]Theme{
	ThemeDefault: {
		Name:       ThemeDefault,
		Primary:    lipgloss.Color("#7D56F4"),
		Secondary:  lipgloss.Color("#04B575"),
		Subtle:     lipgloss.Color("#626262"),
		Overdue:    lipgloss.Color("#FF5F56"),
		Critical:   lipgloss.Color("#FF0000"),
		High:       lipgloss.Color("#FF6B00"),
		Medium:     lipgloss.Color("#FFD700"),
		Low:        lipgloss.Color("#90EE90"),
		Ransomware: lipgloss.Color("#FF1493"),
		URL:        lipgloss.Color("#00BFFF"),
		CWE:        lipgloss.Color("#DDA0DD"),
		Background: lipgloss.Color("#1a1a1a"),
		Foreground: lipgloss.Color("#FFFFFF"),
	},
	ThemeDracula: {
		Name:       ThemeDracula,
		Primary:    lipgloss.Color("#bd93f9"), // Purple
		Secondary:  lipgloss.Color("#50fa7b"), // Green
		Subtle:     lipgloss.Color("#6272a4"), // Comment
		Overdue:    lipgloss.Color("#ff5555"), // Red
		Critical:   lipgloss.Color("#ff5555"), // Red
		High:       lipgloss.Color("#ffb86c"), // Orange
		Medium:     lipgloss.Color("#f1fa8c"), // Yellow
		Low:        lipgloss.Color("#50fa7b"), // Green
		Ransomware: lipgloss.Color("#ff79c6"), // Pink
		URL:        lipgloss.Color("#8be9fd"), // Cyan
		CWE:        lipgloss.Color("#ff79c6"), // Pink
		Background: lipgloss.Color("#282a36"),
		Foreground: lipgloss.Color("#f8f8f2"),
	},
	ThemeCatppuccin: {
		Name:       ThemeCatppuccin,
		Primary:    lipgloss.Color("#cba6f7"), // Mauve
		Secondary:  lipgloss.Color("#a6e3a1"), // Green
		Subtle:     lipgloss.Color("#6c7086"), // Overlay0
		Overdue:    lipgloss.Color("#f38ba8"), // Red
		Critical:   lipgloss.Color("#f38ba8"), // Red
		High:       lipgloss.Color("#fab387"), // Peach
		Medium:     lipgloss.Color("#f9e2af"), // Yellow
		Low:        lipgloss.Color("#a6e3a1"), // Green
		Ransomware: lipgloss.Color("#f5c2e7"), // Pink
		URL:        lipgloss.Color("#89dceb"), // Sky
		CWE:        lipgloss.Color("#f5c2e7"), // Pink
		Background: lipgloss.Color("#1e1e2e"), // Base
		Foreground: lipgloss.Color("#cdd6f4"), // Text
	},
	ThemeNord: {
		Name:       ThemeNord,
		Primary:    lipgloss.Color("#5e81ac"), // Nord10
		Secondary:  lipgloss.Color("#a3be8c"), // Nord14
		Subtle:     lipgloss.Color("#4c566a"), // Nord3
		Overdue:    lipgloss.Color("#bf616a"), // Nord11
		Critical:   lipgloss.Color("#bf616a"), // Nord11
		High:       lipgloss.Color("#d08770"), // Nord12
		Medium:     lipgloss.Color("#ebcb8b"), // Nord13
		Low:        lipgloss.Color("#a3be8c"), // Nord14
		Ransomware: lipgloss.Color("#b48ead"), // Nord15
		URL:        lipgloss.Color("#88c0d0"), // Nord8
		CWE:        lipgloss.Color("#b48ead"), // Nord15
		Background: lipgloss.Color("#2e3440"), // Nord0
		Foreground: lipgloss.Color("#eceff4"), // Nord6
	},
}

// CurrentTheme is the active theme
var CurrentTheme = Themes[ThemeDefault]

// SetTheme changes the active theme
func SetTheme(name ThemeName) {
	if theme, ok := Themes[name]; ok {
		CurrentTheme = theme
		updateStyles()
	}
}

// CycleTheme switches to the next theme
func CycleTheme() ThemeName {
	order := []ThemeName{ThemeDefault, ThemeDracula, ThemeCatppuccin, ThemeNord}
	for i, name := range order {
		if name == CurrentTheme.Name {
			next := order[(i+1)%len(order)]
			SetTheme(next)
			return next
		}
	}
	SetTheme(ThemeDefault)
	return ThemeDefault
}

// updateStyles refreshes the global styles with current theme colors
func updateStyles() {
	PrimaryColor = CurrentTheme.Primary
	SecondaryColor = CurrentTheme.Secondary
	SubtleColor = CurrentTheme.Subtle
	OverdueColor = CurrentTheme.Overdue
	CriticalColor = CurrentTheme.Critical
	HighColor = CurrentTheme.High
	MediumColor = CurrentTheme.Medium
	LowColor = CurrentTheme.Low
	RansomwareColor = CurrentTheme.Ransomware
	URLColor = CurrentTheme.URL
	CWEColor = CurrentTheme.CWE

	// Rebuild styles with new colors
	TitleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(CurrentTheme.Foreground).
		Background(PrimaryColor).
		Padding(0, 1)

	LabelStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(SecondaryColor).
		Width(16)

	ValueStyle = lipgloss.NewStyle().
		Foreground(CurrentTheme.Foreground)

	SubtitleStyle = lipgloss.NewStyle().
		Foreground(SubtleColor)

	URLStyle = lipgloss.NewStyle().
		Foreground(URLColor).
		Underline(true)

	CWEStyle = lipgloss.NewStyle().
		Foreground(CWEColor)

	SelectedItemStyle = lipgloss.NewStyle().
		BorderLeft(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(PrimaryColor).
		PaddingLeft(1)

	NormalItemStyle = lipgloss.NewStyle().
		PaddingLeft(2)

	DescriptionStyle = lipgloss.NewStyle().
		Foreground(CurrentTheme.Foreground).
		Width(80)
}
