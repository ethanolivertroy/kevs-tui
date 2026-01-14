package chat

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethanolivertroy/kevs-tui/internal/agent"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
	"github.com/ethanolivertroy/kevs-tui/internal/palette"
)

// Colors (matching tui/styles.go)
var (
	primaryColor   = lipgloss.Color("#7D56F4")
	secondaryColor = lipgloss.Color("#04B575")
	subtleColor    = lipgloss.Color("#626262")
	errorColor     = lipgloss.Color("#FF5F56")
)

// MessageRole differentiates user vs agent messages
type MessageRole int

const (
	RoleUser MessageRole = iota
	RoleAgent
	RoleSystem
)

// ChatMessage represents a single message in the conversation
type ChatMessage struct {
	Role      MessageRole
	Content   string
	Timestamp time.Time
	IsError   bool
}

// AgentResponseMsg is sent when the agent responds
type AgentResponseMsg struct {
	Content string
	Err     error
}

// Model is the main model for the agent chat TUI
type Model struct {
	ctx        context.Context
	agent      *agent.KEVAgent
	textInput  textinput.Model
	viewport   viewport.Model
	spinner    spinner.Model
	messages   []ChatMessage
	thinking   bool
	width      int
	height     int
	ready      bool
	palette         palette.Model
	currentCVE      *model.VulnerabilityItem // Currently viewed CVE from TUI for context
	glamourRenderer *glamour.TermRenderer    // Cached markdown renderer
	// Text selection
	selecting    bool // Currently dragging to select
	selStartLine int  // Selection start line in viewport content
	selStartCol  int  // Selection start column
	selEndLine   int  // Selection end line
	selEndCol    int  // Selection end column
}

// CurrentCVE returns the currently selected CVE for testing/inspection
func (m Model) CurrentCVE() *model.VulnerabilityItem {
	return m.currentCVE
}

// Chat styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primaryColor).
			Padding(0, 2).
			MarginBottom(1)

	userLabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor)

	agentLabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(secondaryColor)

	userMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(lipgloss.Color("#5A3FBA")).
				Padding(0, 1).
				MarginLeft(2)

	agentMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FFFFFF")).
				BorderLeft(true).
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(secondaryColor).
				PaddingLeft(1).
				MarginLeft(2)

	systemMessageStyle = lipgloss.NewStyle().
				Foreground(subtleColor).
				Italic(true).
				MarginLeft(2)

	errorMessageStyle = lipgloss.NewStyle().
				Foreground(errorColor).
				Italic(true).
				MarginLeft(2)

	footerStyle = lipgloss.NewStyle().
			Foreground(subtleColor)

	dividerStyle = lipgloss.NewStyle().
			Foreground(subtleColor)

	contextStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#86EFAC")). // Light green
			Background(lipgloss.Color("#1E3A2F")). // Dark green background
			Padding(0, 1).
			Bold(true)

	selectionStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#5A4BA3")). // Blue-purple like Claude Code
			Foreground(lipgloss.Color("#FFFFFF"))
)

// NewModel creates a new chat model for interactive agent sessions
func NewModel(ctx context.Context, kevAgent *agent.KEVAgent) Model {
	// Text input setup
	ti := textinput.New()
	ti.Placeholder = "Ask about KEVs..."
	ti.Focus()
	ti.CharLimit = 500
	ti.Width = 80
	ti.Prompt = "> "
	ti.PromptStyle = lipgloss.NewStyle().Foreground(primaryColor).Bold(true)
	ti.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))

	// Spinner for "thinking" state
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(secondaryColor)

	// Welcome message
	welcomeMsg := ChatMessage{
		Role: RoleSystem,
		Content: `Hi, I'm KEVin! I know everything about CISA Known Exploited Vulnerabilities.

Ask me things like:
  "Find Microsoft CVEs with ransomware"
  "What CVEs are overdue?"
  "Get details for CVE-2024-1234"
  "Export ransomware CVEs to markdown"

Commands: /help /clear /exit`,
		Timestamp: time.Now(),
	}

	// Command palette for chat (Crush-style)
	paletteCommands := []palette.Command{
		{Name: "Clear Chat", Key: "/clear", Action: "clear"},
		{Name: "Show Help", Key: "/help", Action: "help"},
		{Name: "Exit Chat", Key: "esc", Action: "exit"},
	}

	// Default dimensions - will be updated on WindowSizeMsg
	defaultWidth := 80
	defaultHeight := 24
	headerHeight := 3
	footerHeight := 5
	viewportHeight := defaultHeight - headerHeight - footerHeight

	// Create viewport upfront so TUI renders immediately
	vp := viewport.New(defaultWidth-4, viewportHeight)
	vp.HighPerformanceRendering = false

	// Create glamour renderer for markdown (cached for performance)
	glamourRenderer, _ := glamour.NewTermRenderer(
		glamour.WithStylePath("dracula"),
		glamour.WithWordWrap(50), // Width for 55-char panel minus padding
	)

	m := Model{
		ctx:             ctx,
		agent:           kevAgent,
		textInput:       ti,
		viewport:        vp,
		spinner:         s,
		messages:        []ChatMessage{welcomeMsg},
		palette:         palette.New(paletteCommands),
		width:           defaultWidth,
		height:          defaultHeight,
		ready:           true, // Start ready immediately
		glamourRenderer: glamourRenderer,
	}

	// Initialize viewport content with welcome message
	m.updateViewportContent()

	return m
}

// Init initializes the chat model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		m.spinner.Tick,
	)
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit

		case "enter":
			if m.thinking {
				return m, nil // Ignore input while thinking
			}

			input := strings.TrimSpace(m.textInput.Value())
			if input == "" {
				return m, nil
			}

			// Clear input
			m.textInput.Reset()

			// Handle slash commands
			if strings.HasPrefix(input, "/") {
				return m.handleCommand(input)
			}

			// Add user message to history
			m.messages = append(m.messages, ChatMessage{
				Role:      RoleUser,
				Content:   input,
				Timestamp: time.Now(),
			})

			// Set thinking state and refresh viewport
			m.thinking = true
			m.updateViewportContent()
			m.viewport.GotoBottom()

			// Send to agent asynchronously
			return m, tea.Batch(m.spinner.Tick, m.sendToAgent(input))

		case "esc":
			m.textInput.Reset()
			return m, nil

		case "pgup", "pgdown", "ctrl+u", "ctrl+d":
			// Scroll viewport
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := 3 // Title
		footerHeight := 5 // Input + help + dividers
		viewportHeight := m.height - headerHeight - footerHeight

		// Update viewport dimensions
		m.viewport.Width = m.width - 4
		m.viewport.Height = viewportHeight
		m.textInput.Width = m.width - 6
		m.updateViewportContent()
		return m, nil

	case spinner.TickMsg:
		if m.thinking {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			m.updateViewportContent() // Update spinner in viewport
			return m, cmd
		}

	case AgentResponseMsg:
		m.thinking = false

		if msg.Err != nil {
			m.messages = append(m.messages, ChatMessage{
				Role:      RoleSystem,
				Content:   "Error: " + msg.Err.Error(),
				Timestamp: time.Now(),
				IsError:   true,
			})
		} else {
			m.messages = append(m.messages, ChatMessage{
				Role:      RoleAgent,
				Content:   msg.Content,
				Timestamp: time.Now(),
			})
		}

		m.updateViewportContent()
		m.viewport.GotoBottom()
		return m, nil

	case model.CVESelectedMsg:
		m.currentCVE = msg.CVE
		return m, nil

	case tea.MouseMsg:
		// Forward mouse wheel events to viewport for scrolling
		if msg.Button == tea.MouseButtonWheelUp || msg.Button == tea.MouseButtonWheelDown {
			m.clearSelection() // Clear selection on scroll
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}

		// Start selection on left click
		if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
			line, col := m.screenToContent(msg.X, msg.Y)
			m.selecting = true
			m.selStartLine, m.selStartCol = line, col
			m.selEndLine, m.selEndCol = line, col
			m.updateViewportContent()
			return m, nil
		}

		// Update selection during drag
		if msg.Action == tea.MouseActionMotion && m.selecting {
			line, col := m.screenToContent(msg.X, msg.Y)
			m.selEndLine, m.selEndCol = line, col
			m.updateViewportContent()
			return m, nil
		}

		// End selection on release
		if msg.Action == tea.MouseActionRelease && msg.Button == tea.MouseButtonLeft {
			m.selecting = false
			return m, nil
		}

		return m, nil // Ignore other mouse events (don't pass to text input)
	}

	// Update text input
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// sanitizeForPrompt removes characters that could enable prompt injection
func sanitizeForPrompt(s string) string {
	// Remove newlines that could break prompt structure
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	// Replace brackets that could inject fake context markers
	s = strings.ReplaceAll(s, "[", "(")
	s = strings.ReplaceAll(s, "]", ")")
	// Collapse multiple spaces
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return strings.TrimSpace(s)
}

// buildEnrichedQuery adds CVE context to a query if available
func buildEnrichedQuery(currentCVE *model.VulnerabilityItem, query string) string {
	if currentCVE == nil {
		return query
	}

	// Sanitize all CVE data to prevent prompt injection
	return fmt.Sprintf(
		"[Context: User is viewing %s - %s (%s, %s). EPSS: %.0f%%, Due: %s]\n\n%s",
		sanitizeForPrompt(currentCVE.CVEID),
		sanitizeForPrompt(currentCVE.VulnerabilityName),
		sanitizeForPrompt(currentCVE.VendorProject),
		sanitizeForPrompt(currentCVE.Product),
		currentCVE.EPSS.Score*100,
		sanitizeForPrompt(currentCVE.DueDateStatus()),
		query,
	)
}

// sendToAgent sends a query to the agent asynchronously
func (m Model) sendToAgent(query string) tea.Cmd {
	// Capture currentCVE for the closure
	currentCVE := m.currentCVE

	return func() tea.Msg {
		enrichedQuery := buildEnrichedQuery(currentCVE, query)
		response, err := m.agent.Chat(m.ctx, enrichedQuery)
		return AgentResponseMsg{Content: response, Err: err}
	}
}

// handleCommand processes slash commands
func (m Model) handleCommand(input string) (Model, tea.Cmd) {
	cmd := strings.ToLower(strings.TrimSpace(input))

	switch {
	case cmd == "/exit" || cmd == "/quit" || cmd == "/q":
		return m, tea.Quit

	case cmd == "/clear":
		m.agent.ClearSession()
		m.messages = []ChatMessage{{
			Role:      RoleSystem,
			Content:   "Conversation cleared. Starting fresh.",
			Timestamp: time.Now(),
		}}
		m.updateViewportContent()
		return m, nil

	case cmd == "/help" || cmd == "/?":
		helpText := `Commands:
  /help, /?    Show this help message
  /clear       Clear conversation and start fresh
  /exit, /q    Exit the agent

Query Examples:
  "search for Apache vulnerabilities"
  "show CVEs with ransomware use"
  "what are the overdue CVEs?"
  "get details for CVE-2024-0001"
  "export all to JSON"
  "show KEV statistics"

Navigation:
  PgUp/PgDn    Scroll conversation history
  Ctrl+C       Quit`
		m.messages = append(m.messages, ChatMessage{
			Role:      RoleSystem,
			Content:   helpText,
			Timestamp: time.Now(),
		})
		m.updateViewportContent()
		m.viewport.GotoBottom()
		return m, nil

	default:
		m.messages = append(m.messages, ChatMessage{
			Role:      RoleSystem,
			Content:   "Unknown command: " + input + ". Type /help for available commands.",
			Timestamp: time.Now(),
			IsError:   true,
		})
		m.updateViewportContent()
		return m, nil
	}
}

// View renders the chat interface
func (m Model) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	var b strings.Builder

	// Title
	title := titleStyle.Render("KEVin - Your KEV Expert")
	b.WriteString("\n")
	b.WriteString(title)
	b.WriteString("\n")

	// CVE context badge on its own line (if viewing a CVE)
	if m.currentCVE != nil {
		badge := contextStyle.Render(m.currentCVE.CVEID)
		b.WriteString(badge)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Viewport with messages
	b.WriteString(m.viewport.View())
	b.WriteString("\n")

	// Divider
	divider := dividerStyle.Render(strings.Repeat("─", m.width-2))
	b.WriteString(divider)
	b.WriteString("\n")

	// Text input
	b.WriteString("  ")
	b.WriteString(m.textInput.View())
	b.WriteString("\n")

	// Help footer
	if m.thinking {
		b.WriteString(footerStyle.Render("  " + m.spinner.View() + " KEVin is thinking..."))
	} else {
		b.WriteString(footerStyle.Render("  PgUp/Dn scroll  |  /help /clear /exit"))
	}

	return b.String()
}

// updateViewportContent rebuilds the viewport content from messages
func (m *Model) updateViewportContent() {
	var content strings.Builder

	for _, msg := range m.messages {
		content.WriteString(m.renderMessage(msg))
		content.WriteString("\n\n")
	}

	// Show thinking indicator at bottom
	if m.thinking {
		thinkingStyle := lipgloss.NewStyle().
			Foreground(secondaryColor).
			Italic(true).
			MarginLeft(2)
		content.WriteString(thinkingStyle.Render(m.spinner.View() + " KEVin is thinking..."))
		content.WriteString("\n")
	}

	// Apply selection highlighting to final content
	finalContent := content.String()
	if m.hasSelection() {
		finalContent = m.applySelectionHighlight(finalContent)
	}

	m.viewport.SetContent(finalContent)
}

// renderMessage formats a single message
func (m Model) renderMessage(msg ChatMessage) string {
	var b strings.Builder

	switch msg.Role {
	case RoleUser:
		b.WriteString(userLabelStyle.Render("You:"))
		b.WriteString("\n")
		// Wrap long user messages
		wrapped := wrapText(msg.Content, m.width-8)
		b.WriteString(userMessageStyle.Render(wrapped))

	case RoleAgent:
		b.WriteString(agentLabelStyle.Render("KEVin:"))
		b.WriteString("\n")
		// Render agent messages with markdown styling
		rendered := m.renderMarkdown(msg.Content)
		b.WriteString(rendered)

	case RoleSystem:
		if msg.IsError {
			b.WriteString(errorMessageStyle.Render(msg.Content))
		} else {
			b.WriteString(systemMessageStyle.Render(msg.Content))
		}
	}

	return b.String()
}

// renderMarkdown renders markdown content using cached glamour renderer
func (m Model) renderMarkdown(content string) string {
	width := m.width - 10
	if width < 40 {
		width = 40
	}

	// Use cached renderer if available, fallback to plain text
	if m.glamourRenderer == nil {
		return agentMessageStyle.Render(wrapText(content, width))
	}

	out, err := m.glamourRenderer.Render(content)
	if err != nil {
		return agentMessageStyle.Render(wrapText(content, width))
	}

	// Trim extra whitespace glamour adds
	out = strings.TrimSpace(out)

	// Add left margin for consistency with other messages
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}

// wrapText wraps text to the specified width
func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}

	var result strings.Builder
	lines := strings.Split(text, "\n")

	for i, line := range lines {
		if i > 0 {
			result.WriteString("\n")
		}

		// Handle lines that are already short enough
		if len(line) <= width {
			result.WriteString(line)
			continue
		}

		// Wrap long lines
		words := strings.Fields(line)
		currentLine := ""
		for _, word := range words {
			if currentLine == "" {
				currentLine = word
			} else if len(currentLine)+1+len(word) <= width {
				currentLine += " " + word
			} else {
				result.WriteString(currentLine)
				result.WriteString("\n")
				currentLine = word
			}
		}
		if currentLine != "" {
			result.WriteString(currentLine)
		}
	}

	return result.String()
}

// handlePaletteAction handles actions from the command palette
func (m Model) handlePaletteAction(action string) (tea.Model, tea.Cmd) {
	switch action {
	case "clear":
		m.agent.ClearSession()
		m.messages = []ChatMessage{{
			Role:      RoleSystem,
			Content:   "Conversation cleared. Starting fresh.",
			Timestamp: time.Now(),
		}}
		m.updateViewportContent()
		return m, nil
	case "help":
		helpText := `Commands:
  /help, /?    Show this help message
  /clear       Clear conversation and start fresh
  /exit, /q    Exit the agent

Query Examples:
  "search for Apache vulnerabilities"
  "show CVEs with ransomware use"
  "what are the overdue CVEs?"
  "get details for CVE-2024-0001"
  "export all to JSON"
  "show KEV statistics"

Navigation:
  PgUp/PgDn    Scroll conversation history
  Ctrl+C       Quit`
		m.messages = append(m.messages, ChatMessage{
			Role:      RoleSystem,
			Content:   helpText,
			Timestamp: time.Now(),
		})
		m.updateViewportContent()
		m.viewport.GotoBottom()
		return m, nil
	case "exit":
		return m, tea.Quit
	}
	return m, nil
}

// screenToContent converts screen coordinates to content line/column
func (m Model) screenToContent(screenX, screenY int) (line, col int) {
	// Account for header (title + optional badge + spacing)
	viewportStartY := 4
	if m.currentCVE != nil {
		viewportStartY = 5 // Badge adds a line
	}

	// Convert screen Y to content line
	relativeY := screenY - viewportStartY
	if relativeY < 0 {
		relativeY = 0
	}
	line = relativeY + m.viewport.YOffset

	// Column is roughly screenX minus left margin
	col = screenX - 2
	if col < 0 {
		col = 0
	}

	return line, col
}

// clearSelection clears the current text selection
func (m *Model) clearSelection() {
	m.selecting = false
	m.selStartLine, m.selStartCol = 0, 0
	m.selEndLine, m.selEndCol = 0, 0
}

// hasSelection returns true if there is an active selection
func (m Model) hasSelection() bool {
	return m.selStartLine != m.selEndLine || m.selStartCol != m.selEndCol
}

// normalizeSelection ensures start is before end
func (m Model) normalizeSelection() (startLine, startCol, endLine, endCol int) {
	if m.selStartLine < m.selEndLine ||
		(m.selStartLine == m.selEndLine && m.selStartCol <= m.selEndCol) {
		return m.selStartLine, m.selStartCol, m.selEndLine, m.selEndCol
	}
	return m.selEndLine, m.selEndCol, m.selStartLine, m.selStartCol
}

// applySelectionHighlight applies selection styling to content (ANSI-aware)
func (m Model) applySelectionHighlight(content string) string {
	lines := strings.Split(content, "\n")

	// Normalize selection (start before end)
	startLine, startCol, endLine, endCol := m.normalizeSelection()

	for i := startLine; i <= endLine && i < len(lines); i++ {
		line := lines[i]

		// Calculate selection bounds for this line
		selStart := 0
		selEnd := visibleLength(line)

		if i == startLine {
			selStart = startCol
		}
		if i == endLine {
			selEnd = endCol
		}

		// Use ANSI-aware slicing
		lines[i] = ansiSliceWithHighlight(line, selStart, selEnd)
	}

	return strings.Join(lines, "\n")
}

// visibleLength returns the visible character count excluding ANSI escape sequences
func visibleLength(s string) int {
	count := 0
	inEscape := false
	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		count++
	}
	return count
}

// ansiSliceWithHighlight applies highlight to a portion of an ANSI-styled string
// It preserves all ANSI escape sequences while only highlighting visible characters
func ansiSliceWithHighlight(s string, start, end int) string {
	var result strings.Builder
	visiblePos := 0
	inEscape := false
	var escapeSeq strings.Builder

	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			escapeSeq.Reset()
			escapeSeq.WriteRune(r)
			continue
		}

		if inEscape {
			escapeSeq.WriteRune(r)
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				// End of escape sequence - write it through unchanged
				result.WriteString(escapeSeq.String())
				inEscape = false
			}
			continue
		}

		// Regular visible character
		if visiblePos >= start && visiblePos < end {
			// Inside selection - apply highlight
			result.WriteString(selectionStyle.Render(string(r)))
		} else {
			result.WriteRune(r)
		}
		visiblePos++
	}

	return result.String()
}
