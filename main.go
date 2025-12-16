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
	"github.com/ethanolivertroy/kevs-tui/internal/tui"
)

// Layout constants (Crush-style)
const (
	AgentPanelWidth    = 45  // Fixed width for agent sidebar
	CompactBreakpoint  = 100 // Below this width, hide agent panel
	HeaderHeight       = 1
	MouseThrottleMs    = 15
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
	compact          bool // Hide agent panel in compact mode

	// Dimensions
	width  int
	height int
}

func newAppModel() AppModel {
	return AppModel{
		tuiModel:     tui.NewModel(),
		focusedPanel: PanelBrowser,
	}
}

func (m AppModel) Init() tea.Cmd {
	cmds := []tea.Cmd{m.tuiModel.Init()}

	// Initialize agent immediately if API key is set
	if os.Getenv("GEMINI_API_KEY") != "" {
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
		// Send initial size to agent
		if m.width > 0 && !m.compact {
			agentMsg := tea.WindowSizeMsg{Width: AgentPanelWidth, Height: m.height}
			var agentCmd tea.Cmd
			m.agentModel, agentCmd = m.agentModel.Update(agentMsg)
			cmds = append(cmds, agentCmd)
		}
		return m, tea.Batch(cmds...)

	case agentInitErrorMsg:
		m.agentError = msg.err.Error()
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		// Tab switches focus between panels (only if not compact)
		if msg.String() == "tab" && !m.compact {
			if m.focusedPanel == PanelBrowser {
				m.focusedPanel = PanelAgent
			} else {
				m.focusedPanel = PanelBrowser
			}
			return m, nil
		}

		// Route to focused panel
		if m.focusedPanel == PanelAgent && m.agentModel != nil && !m.compact {
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

		// Handle click for panel switching
		if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft && !m.compact {
			browserWidth := m.width - AgentPanelWidth
			if msg.X < browserWidth {
				m.focusedPanel = PanelBrowser
			} else {
				m.focusedPanel = PanelAgent
			}
		}

		// Route to appropriate panel
		if m.focusedPanel == PanelAgent && m.agentModel != nil && !m.compact {
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
			var cmd tea.Cmd
			m.tuiModel, cmd = m.tuiModel.Update(msg)
			cmds = append(cmds, cmd)
		} else {
			browserWidth := m.width - AgentPanelWidth
			browserMsg := tea.WindowSizeMsg{Width: browserWidth, Height: m.height}
			var cmd tea.Cmd
			m.tuiModel, cmd = m.tuiModel.Update(browserMsg)
			cmds = append(cmds, cmd)

			if m.agentModel != nil {
				agentMsg := tea.WindowSizeMsg{Width: AgentPanelWidth, Height: m.height}
				var agentCmd tea.Cmd
				m.agentModel, agentCmd = m.agentModel.Update(agentMsg)
				cmds = append(cmds, agentCmd)
			}
		}
		return m, tea.Batch(cmds...)

	case tui.OpenAgentMsg:
		if !m.compact {
			m.focusedPanel = PanelAgent
		}
		return m, nil
	}

	// Route other messages to focused panel only (prevents flickering from spinner ticks)
	if m.focusedPanel == PanelAgent && m.agentModel != nil && !m.compact {
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

	if m.compact {
		// Compact mode: just browser, full width
		return m.tuiModel.View()
	}

	// Normal mode: browser + agent sidebar
	browserWidth := m.width - AgentPanelWidth

	// Browser panel (no extra border, let internal component handle it)
	browserView := lipgloss.NewStyle().
		Width(browserWidth).
		Height(m.height).
		Render(m.tuiModel.View())

	// Agent sidebar with border
	agentBorder := borderUnfocused
	if m.focusedPanel == PanelAgent {
		agentBorder = borderFocused
	}

	agentStyle := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true). // Left border only
		BorderForeground(agentBorder).
		Width(AgentPanelWidth - 1).
		Height(m.height)

	var agentContent string
	if m.agentModel != nil {
		agentContent = m.agentModel.View()
	} else if m.agentError != "" {
		agentContent = m.renderError()
	} else if os.Getenv("GEMINI_API_KEY") == "" {
		agentContent = m.renderNoApiKey()
	} else {
		agentContent = m.renderLoading()
	}

	agentView := agentStyle.Render(agentContent)

	return lipgloss.JoinHorizontal(lipgloss.Top, browserView, agentView)
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
		Render("Set GEMINI_API_KEY\nto enable")

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

func main() {
	agentMode := flag.Bool("agent", false, "Start in agent-only mode")
	agentShort := flag.Bool("a", false, "Start in agent-only mode (shorthand)")
	version := flag.Bool("version", false, "Print version and exit")
	help := flag.Bool("help", false, "Print help and exit")
	flag.BoolVar(help, "h", false, "Print help and exit (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `KEVs TUI - Terminal UI for CISA Known Exploited Vulnerabilities

Usage:
  kevs-tui [flags] [query...]

Modes:
  Default     KEV browser with KEVin AI sidebar
  Agent       Chat with KEVin AI only

Flags:
  -a, --agent     Start in agent-only mode (requires GEMINI_API_KEY)
  -h, --help      Print this help message
      --version   Print version information

Examples:
  kevs-tui                           # Browser with agent sidebar
  kevs-tui --agent                   # Agent-only mode
  kevs-tui -a "Microsoft vulns"      # One-shot query

Environment:
  GEMINI_API_KEY  Required for KEVin agent

Keyboard:
  Tab     Switch focus between panels
  Click   Click to focus panel
  Ctrl+C  Quit
`)
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *version {
		fmt.Println("kevs-tui v0.1.0")
		os.Exit(0)
	}

	if *agentMode || *agentShort {
		args := flag.Args()
		if err := cmd.RunAgent(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if flag.NArg() > 0 {
		if err := cmd.RunAgent(flag.Args()); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	p := tea.NewProgram(newAppModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
