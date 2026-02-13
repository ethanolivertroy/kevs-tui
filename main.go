package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethanolivertroy/kevs-tui/cmd"
	"github.com/ethanolivertroy/kevs-tui/internal/agent"
	"github.com/ethanolivertroy/kevs-tui/internal/chat"
	"github.com/ethanolivertroy/kevs-tui/internal/llm"
	"github.com/ethanolivertroy/kevs-tui/internal/model"
	"github.com/ethanolivertroy/kevs-tui/internal/tui"
)

// Layout constants (Crush-style)
const (
	AgentPanelWidth     = 55  // Fixed width for agent sidebar
	CompactBreakpoint   = 100 // Below this width, hide agent panel
	BrowserHeaderHeight = 0   // No separate header - TUI list has its own title
	AgentHeaderHeight   = 0   // No separate header - chat model has its own title
	MouseThrottleMs     = 15
)

// Panel types for focus management
type PanelType int

const (
	PanelBrowser PanelType = iota
	PanelAgent
)

// Colors
var (
	primaryColor    = lipgloss.Color("#7D56F4")
	secondaryColor  = lipgloss.Color("#04B575")
	subtleColor     = lipgloss.Color("#626262")
	borderFocused   = lipgloss.Color("#7D56F4")
	borderUnfocused = lipgloss.Color("#3a3a3a")
)

// Mouse throttling
var lastMouseEvent time.Time

// AppModel handles Crush-style layout with KEV browser and agent sidebar
type AppModel struct {
	// Models
	tuiModel   tea.Model
	agentModel tea.Model

	// State
	agentInitialized bool
	agentError       string
	focusedPanel     PanelType
	compact          bool // Hide agent panel in compact mode (window too narrow)
	agentVisible     bool // User-controlled visibility (toggle with \)
	pendingCVE       *model.VulnerabilityItem // Stores CVE context until agent initializes

	// Dimensions
	width  int
	height int
}

func newAppModel() AppModel {
	// Set default dimensions so TUI renders immediately
	// These will be updated on WindowSizeMsg
	defaultWidth := 120
	defaultHeight := 30

	return AppModel{
		tuiModel:     tui.NewModel(),
		focusedPanel: PanelBrowser,
		agentVisible: true, // Visible by default, toggle with \
		width:        defaultWidth,
		height:       defaultHeight,
	}
}

func (m AppModel) Init() tea.Cmd {
	cmds := []tea.Cmd{m.tuiModel.Init()}

	// Initialize agent immediately if any LLM provider is configured
	cfg := llm.ConfigFromEnv()
	if err := cfg.Validate(); err == nil {
		cmds = append(cmds, m.initAgent())
	}

	return tea.Batch(cmds...)
}

func (m AppModel) initAgent() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		kevAgent, err := agent.New(ctx)
		if err != nil {
			return agentInitErrorMsg{err: err}
		}
		return agentInitMsg{agent: kevAgent, ctx: ctx}
	}
}

type agentInitMsg struct {
	agent *agent.KEVAgent
	ctx   context.Context
}

type agentInitErrorMsg struct {
	err error
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case agentInitMsg:
		m.agentModel = chat.NewModel(msg.ctx, msg.agent)
		m.agentInitialized = true
		initCmd := m.agentModel.Init()
		cmds = append(cmds, initCmd)
		// Send initial size to agent (subtract header height)
		if m.width > 0 && !m.compact {
			agentMsg := tea.WindowSizeMsg{Width: AgentPanelWidth, Height: m.height - AgentHeaderHeight}
			var agentCmd tea.Cmd
			m.agentModel, agentCmd = m.agentModel.Update(agentMsg)
			cmds = append(cmds, agentCmd)
		}
		// Apply any pending CVE context that arrived before agent initialized
		if m.pendingCVE != nil {
			cveMsg := model.CVESelectedMsg{CVE: m.pendingCVE}
			var cveCmd tea.Cmd
			m.agentModel, cveCmd = m.agentModel.Update(cveMsg)
			cmds = append(cmds, cveCmd)
		}
		return m, tea.Batch(cmds...)

	case agentInitErrorMsg:
		m.agentError = msg.err.Error()
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		// Backslash toggles agent panel visibility (like Crush)
		if msg.String() == "\\" && !m.compact {
			m.agentVisible = !m.agentVisible
			// If hiding panel, switch focus to browser
			if !m.agentVisible {
				m.focusedPanel = PanelBrowser
			}
			return m, nil
		}

		// Tab switches focus between panels (only if agent visible)
		if msg.String() == "tab" && !m.compact && m.agentVisible {
			if m.focusedPanel == PanelBrowser {
				m.focusedPanel = PanelAgent
			} else {
				m.focusedPanel = PanelBrowser
			}
			return m, nil
		}

		// Route to focused panel
		if m.focusedPanel == PanelAgent && m.agentModel != nil && !m.compact && m.agentVisible {
			var cmd tea.Cmd
			m.agentModel, cmd = m.agentModel.Update(msg)
			return m, cmd
		} else {
			var cmd tea.Cmd
			m.tuiModel, cmd = m.tuiModel.Update(msg)
			return m, cmd
		}

	case tea.MouseMsg:
		// Throttle mouse events
		now := time.Now()
		if now.Sub(lastMouseEvent) < MouseThrottleMs*time.Millisecond {
			return m, nil
		}
		lastMouseEvent = now

		// Handle click for panel switching (only when agent is visible)
		if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft && !m.compact && m.agentVisible {
			browserWidth := m.width - AgentPanelWidth
			if msg.X < browserWidth {
				m.focusedPanel = PanelBrowser
			} else {
				m.focusedPanel = PanelAgent
			}
		}

		// Route to appropriate panel
		if m.focusedPanel == PanelAgent && m.agentModel != nil && !m.compact && m.agentVisible {
			adjustedMsg := msg
			adjustedMsg.X = msg.X - (m.width - AgentPanelWidth)
			var cmd tea.Cmd
			m.agentModel, cmd = m.agentModel.Update(adjustedMsg)
			return m, cmd
		} else {
			var cmd tea.Cmd
			m.tuiModel, cmd = m.tuiModel.Update(msg)
			return m, cmd
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.compact = msg.Width < CompactBreakpoint

		var cmds []tea.Cmd
		if m.compact {
			// In compact mode, subtract browser header height
			compactMsg := tea.WindowSizeMsg{Width: msg.Width, Height: m.height - BrowserHeaderHeight}
			var cmd tea.Cmd
			m.tuiModel, cmd = m.tuiModel.Update(compactMsg)
			cmds = append(cmds, cmd)
		} else {
			browserWidth := m.width - AgentPanelWidth
			// Subtract header height so content doesn't overflow
			browserMsg := tea.WindowSizeMsg{Width: browserWidth, Height: m.height - BrowserHeaderHeight}
			var cmd tea.Cmd
			m.tuiModel, cmd = m.tuiModel.Update(browserMsg)
			cmds = append(cmds, cmd)

			if m.agentModel != nil {
				// Subtract agent header height for KEVin panel
				agentMsg := tea.WindowSizeMsg{Width: AgentPanelWidth, Height: m.height - AgentHeaderHeight}
				var agentCmd tea.Cmd
				m.agentModel, agentCmd = m.agentModel.Update(agentMsg)
				cmds = append(cmds, agentCmd)
			}
		}
		return m, tea.Batch(cmds...)

	case tui.OpenAgentMsg:
		if !m.compact {
			m.agentVisible = true // Show panel when Ctrl+K pressed
			m.focusedPanel = PanelAgent
		}
		return m, nil

	case model.CVESelectedMsg:
		// Route CVE selection to chat model for context-aware queries
		// Always store as pending in case agent needs to be re-initialized
		m.pendingCVE = msg.CVE
		if m.agentModel != nil {
			var cmd tea.Cmd
			m.agentModel, cmd = m.agentModel.Update(msg)
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case chat.AgentResponseMsg:
		// Always route agent responses to chat model regardless of focus
		// This prevents KEVin from freezing when user switches panels during a request
		if m.agentModel != nil {
			var cmd tea.Cmd
			m.agentModel, cmd = m.agentModel.Update(msg)
			return m, cmd
		}
		return m, nil

	case chat.StreamChunkMsg, chat.ToolCallMsg, chat.StreamDoneMsg, chat.StreamErrorMsg:
		// Always route streaming events to chat model regardless of focus
		// Same rationale as AgentResponseMsg — prevents lost events during panel switch
		if m.agentModel != nil {
			var cmd tea.Cmd
			m.agentModel, cmd = m.agentModel.Update(msg)
			return m, cmd
		}
		return m, nil
	}

	// Route other messages to focused panel only (prevents flickering from spinner ticks)
	if m.focusedPanel == PanelAgent && m.agentModel != nil && !m.compact && m.agentVisible {
		var cmd tea.Cmd
		m.agentModel, cmd = m.agentModel.Update(msg)
		return m, cmd
	}
	var cmd tea.Cmd
	m.tuiModel, cmd = m.tuiModel.Update(msg)
	return m, cmd
}

func (m AppModel) View() string {
	// Don't render until we have valid dimensions
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	// Compact mode or agent hidden: just browser, full width
	if m.compact || !m.agentVisible {
		return m.tuiModel.View()
	}

	// Normal mode: browser + agent sidebar
	browserWidth := m.width - AgentPanelWidth

	browserView := lipgloss.NewStyle().
		Width(browserWidth).
		Height(m.height).
		Render(m.tuiModel.View())

	// Agent sidebar
	agentBorder := borderUnfocused
	if m.focusedPanel == PanelAgent {
		agentBorder = borderFocused
	}

	var agentContent string
	if m.agentModel != nil {
		agentContent = m.agentModel.View()
	} else if m.agentError != "" {
		agentContent = m.renderError()
	} else {
		// Check if any LLM provider is configured
		cfg := llm.ConfigFromEnv()
		if err := cfg.Validate(); err != nil {
			agentContent = m.renderNoApiKey()
		} else {
			agentContent = m.renderLoading()
		}
	}

	agentStyle := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true). // Left border only
		BorderForeground(agentBorder).
		Width(AgentPanelWidth - 1).
		Height(m.height)

	agentView := agentStyle.Render(agentContent)

	return lipgloss.JoinHorizontal(lipgloss.Top, browserView, agentView)
}

// getProviderSetupHelp returns setup instructions for the configured provider
func getProviderSetupHelp() string {
	cfg := llm.ConfigFromEnv()
	switch cfg.Provider {
	case "gemini":
		return "Set GEMINI_API_KEY\nto enable"
	case "vertex":
		return "Set VERTEX_PROJECT\nand VERTEX_LOCATION"
	case "ollama":
		return "Start Ollama:\n  ollama serve"
	case "openrouter":
		return "Set OPENROUTER_API_KEY\nto enable"
	default:
		return "Configure LLM_PROVIDER\nand credentials"
	}
}

func (m AppModel) renderNoApiKey() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(primaryColor).
		Render("KEVin")

	subtitle := lipgloss.NewStyle().
		Foreground(subtleColor).
		Render("AI Assistant")

	instruction := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#888")).
		Render(getProviderSetupHelp())

	return lipgloss.JoinVertical(lipgloss.Center,
		"",
		title,
		subtitle,
		"",
		instruction,
	)
}

func (m AppModel) renderError() string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FF5F56")).
		Render(fmt.Sprintf("Error:\n%s", m.agentError))
}

func (m AppModel) renderLoading() string {
	return lipgloss.NewStyle().
		Foreground(subtleColor).
		Render("Loading KEVin...")
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `KEVs TUI - Terminal UI for CISA Known Exploited Vulnerabilities

Usage:
  kevs-tui [command] [args...]

Commands:
  (default)   KEV browser with KEVin AI sidebar
  agent       Chat with KEVin AI only
  serve       Run as A2A server

Examples:
  kevs-tui                           # Browser with agent sidebar
  kevs-tui agent                     # Interactive agent chat
  kevs-tui agent "Microsoft vulns"   # One-shot query
  kevs-tui serve                     # Start A2A server on localhost:8001
  kevs-tui serve --port 9000         # Start A2A server on custom port
  kevs-tui serve --host 0.0.0.0      # Bind to all interfaces (INSECURE)

Environment:
  LLM_PROVIDER      LLM provider: gemini (default), vertex, or ollama
  LLM_MODEL         Model name (e.g., gemini-2.0-flash, llama3.2)
  GEMINI_API_KEY    Required for Gemini provider
  VERTEX_PROJECT    GCP project ID (required for Vertex AI)
  VERTEX_LOCATION   GCP region (required for Vertex AI, e.g., us-central1)
  OLLAMA_URL        Ollama server URL (default: http://localhost:11434)

Keyboard (TUI mode):
  \       Toggle KEVin panel
  Tab     Switch focus between panels
  Ctrl+K  Open/focus KEVin
  Ctrl+P  Open command palette
  Ctrl+C  Quit
`)
}

func main() {
	// No args = default TUI mode
	if len(os.Args) < 2 {
		runDefaultTUI()
		return
	}

	// Handle subcommands
	switch os.Args[1] {
	case "serve":
		// Parse serve-specific flags
		serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
		port := serveCmd.Int("port", 8001, "Port for A2A server")
		host := serveCmd.String("host", "127.0.0.1", "Host to bind (use 0.0.0.0 for all interfaces - INSECURE)")
		serveCmd.Parse(os.Args[2:])

		if err := cmd.RunServe(*port, *host); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "agent":
		// Args after "agent" are the query
		args := os.Args[2:]
		if err := cmd.RunAgent(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "help", "--help", "-h":
		printUsage()

	case "version", "--version":
		fmt.Println("kevs-tui v0.1.0")

	default:
		// Unknown command - treat as query to agent
		if err := cmd.RunAgent(os.Args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func runDefaultTUI() {
	p := tea.NewProgram(newAppModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
