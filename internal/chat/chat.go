package chat

import (
	"context"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethanolivertroy/kevs-tui/internal/agent"
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
	ctx       context.Context
	agent     *agent.KEVAgent
	textInput textinput.Model
	viewport  viewport.Model
	spinner   spinner.Model
	messages  []ChatMessage
	thinking  bool
	width     int
	height    int
	ready     bool
	palette   palette.Model
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

Commands: /help /clear /exit | Ctrl+P for command palette`,
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

	m := Model{
		ctx:       ctx,
		agent:     kevAgent,
		textInput: ti,
		viewport:  vp,
		spinner:   s,
		messages:  []ChatMessage{welcomeMsg},
		palette:   palette.New(paletteCommands),
		width:     defaultWidth,
		height:    defaultHeight,
		ready:     true, // Start ready immediately
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

	// Handle palette actions
	if action, ok := msg.(palette.SelectedAction); ok {
		return m.handlePaletteAction(string(action))
	}

	// If palette is active, route all input to it first
	if m.palette.Active {
		var cmd tea.Cmd
		m.palette, cmd = m.palette.Update(msg)
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit

		case "ctrl+p":
			// Open command palette
			m.palette.SetSize(40, 10)
			m.palette.Open()
			return m, nil

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
	}

	// Update text input
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// sendToAgent sends a query to the agent asynchronously
func (m Model) sendToAgent(query string) tea.Cmd {
	return func() tea.Msg {
		response, err := m.agent.Chat(m.ctx, query)
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
	b.WriteString("\n\n")

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
		b.WriteString(footerStyle.Render("  /help  /clear  /exit  |  Ctrl+P commands  |  Ctrl+C quit"))
	}

	content := b.String()

	// Overlay command palette if active
	if m.palette.Active {
		content = m.palette.Overlay(content, m.width, m.height)
	}

	return content
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

	m.viewport.SetContent(content.String())
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

// renderMarkdown renders markdown content using glamour
func (m Model) renderMarkdown(content string) string {
	width := m.width - 10
	if width < 40 {
		width = 40
	}

	r, err := glamour.NewTermRenderer(
		glamour.WithStylePath("dark"),
		glamour.WithWordWrap(width),
	)
	if err != nil {
		// Fallback to plain text with wrapping
		return agentMessageStyle.Render(wrapText(content, width))
	}

	out, err := r.Render(content)
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
  Ctrl+P       Open command palette
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
