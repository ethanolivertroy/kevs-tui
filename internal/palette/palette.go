package palette

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Colors (matching tui/styles.go)
var (
	primaryColor   = lipgloss.Color("#7D56F4")
	secondaryColor = lipgloss.Color("#04B575")
	subtleColor    = lipgloss.Color("#626262")
)

// Styles for the palette (Crush-style)
var (
	// Header with striped pattern like Crush
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primaryColor)

	// Main container
	paletteStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor)

	// Selected item - magenta background like Crush
	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#FF00FF")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Bold(true)

	// Normal item
	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF"))

	// Shortcut on right side
	shortcutStyle = lipgloss.NewStyle().
			Foreground(subtleColor)

	// Footer hints
	footerStyle = lipgloss.NewStyle().
			Foreground(subtleColor)

	// Input prompt
	promptStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)
)

// Command represents a single command in the palette
type Command struct {
	Name   string // Display name
	Key    string // Keyboard shortcut
	Action string // Action identifier returned when selected
}

// Model is the command palette model
type Model struct {
	commands  []Command
	filtered  []Command
	textInput textinput.Model
	selected  int
	Active    bool
	width     int
	height    int
}

// New creates a new command palette with the given commands
func New(commands []Command) Model {
	ti := textinput.New()
	ti.Placeholder = "Type to filter"
	ti.Prompt = "> "
	ti.PromptStyle = promptStyle
	ti.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
	ti.CharLimit = 50

	return Model{
		commands:  commands,
		filtered:  commands,
		textInput: ti,
		selected:  0,
		Active:    false,
		width:     60,
		height:    20,
	}
}

// SetSize sets the palette dimensions
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.textInput.Width = width - 6
}

// Open activates the palette
func (m *Model) Open() {
	m.Active = true
	m.textInput.Reset()
	m.textInput.Focus()
	m.filtered = m.commands
	m.selected = 0
}

// Close deactivates the palette
func (m *Model) Close() {
	m.Active = false
	m.textInput.Blur()
}

// SelectedAction returns the action string of the currently selected command
type SelectedAction string

// Update handles messages for the palette
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if !m.Active {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.Close()
			return m, nil

		case "enter":
			if len(m.filtered) > 0 && m.selected < len(m.filtered) {
				action := m.filtered[m.selected].Action
				m.Close()
				return m, func() tea.Msg { return SelectedAction(action) }
			}
			return m, nil

		case "up":
			if m.selected > 0 {
				m.selected--
			} else {
				m.selected = len(m.filtered) - 1 // Wrap to bottom
			}
			return m, nil

		case "down":
			if m.selected < len(m.filtered)-1 {
				m.selected++
			} else {
				m.selected = 0 // Wrap to top
			}
			return m, nil

		case "ctrl+c":
			m.Close()
			return m, nil
		}
	}

	// Update text input
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)

	// Filter commands based on input
	m.filterCommands()

	return m, cmd
}

// filterCommands filters the command list based on the current input
func (m *Model) filterCommands() {
	query := strings.ToLower(m.textInput.Value())

	if query == "" {
		m.filtered = m.commands
	} else {
		var filtered []Command
		for _, cmd := range m.commands {
			if strings.Contains(strings.ToLower(cmd.Name), query) ||
				strings.Contains(strings.ToLower(cmd.Key), query) {
				filtered = append(filtered, cmd)
			}
		}
		m.filtered = filtered
	}

	// Adjust selection if out of bounds
	if m.selected >= len(m.filtered) {
		m.selected = max(0, len(m.filtered)-1)
	}
}

// View renders the palette (Crush-style)
func (m Model) View() string {
	if !m.Active {
		return ""
	}

	// Calculate content width
	contentWidth := m.width - 2

	// Build the striped header like Crush
	title := " Commands "
	stripeChar := "/"
	stripeLen := (contentWidth - len(title)) / 2
	stripe := strings.Repeat(stripeChar, stripeLen)
	header := headerStyle.Width(contentWidth).Render(stripe + title + stripe)

	var lines []string
	lines = append(lines, header)

	// Filter input
	lines = append(lines, " "+m.textInput.View())
	lines = append(lines, "")

	// Command list
	maxVisible := min(12, len(m.filtered))

	if len(m.filtered) == 0 {
		lines = append(lines, footerStyle.Render("  No matching commands"))
	} else {
		for i := 0; i < maxVisible; i++ {
			cmd := m.filtered[i]

			// Calculate padding for right-aligned shortcut
			nameWidth := contentWidth - 12 // Leave room for shortcut
			paddedName := fmt.Sprintf("%-*s", nameWidth, truncate(cmd.Name, nameWidth))

			shortcut := ""
			if cmd.Key != "" {
				shortcut = shortcutStyle.Render(cmd.Key)
			}

			var line string
			if i == m.selected {
				// Full width highlight like Crush
				line = selectedStyle.Width(contentWidth).Render(paddedName + shortcut)
			} else {
				line = normalStyle.Render(paddedName) + shortcut
			}
			lines = append(lines, line)
		}
	}

	// Footer with navigation hints
	lines = append(lines, "")
	footer := footerStyle.Render("↑↓ choose • enter confirm • esc cancel")
	lines = append(lines, footer)

	content := strings.Join(lines, "\n")
	return paletteStyle.Width(m.width).Render(content)
}

// Overlay renders the palette centered over the given background content
func (m Model) Overlay(background string, termWidth, termHeight int) string {
	if !m.Active {
		return background
	}

	palette := m.View()
	paletteWidth := lipgloss.Width(palette)
	paletteHeight := lipgloss.Height(palette)

	// Calculate center position
	x := (termWidth - paletteWidth) / 2
	y := (termHeight - paletteHeight) / 3 // Slightly above center

	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	// Split background into lines
	bgLines := strings.Split(background, "\n")
	paletteLines := strings.Split(palette, "\n")

	// Ensure we have enough background lines
	for len(bgLines) < termHeight {
		bgLines = append(bgLines, "")
	}

	// Overlay palette onto background
	for i, paletteLine := range paletteLines {
		bgY := y + i
		if bgY < 0 || bgY >= len(bgLines) {
			continue
		}

		// Build the overlaid line
		bgLine := bgLines[bgY]

		// Pad background line if needed
		for len(bgLine) < x+paletteWidth {
			bgLine += " "
		}

		// Create new line with palette overlaid
		newLine := ""
		if x > 0 {
			newLine = truncateRunes(bgLine, x)
		}
		newLine += paletteLine

		// Add remaining background
		remaining := x + lipgloss.Width(paletteLine)
		if remaining < len(bgLine) {
			newLine += bgLine[remaining:]
		}

		bgLines[bgY] = newLine
	}

	return strings.Join(bgLines, "\n")
}

// Helper functions
func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

func truncateRunes(s string, n int) string {
	runes := []rune(s)
	if n >= len(runes) {
		return s
	}
	return string(runes[:n])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
