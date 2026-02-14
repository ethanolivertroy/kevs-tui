# AGENTS.md

This guide helps AI agents work effectively in this repository.

## Project Overview

**kevs-tui** is a Terminal UI (TUI) application for browsing CISA Known Exploited Vulnerabilities (KEV) catalog with an integrated AI assistant (KEVin).

- **Language**: Go 1.26.0
- **Module**: `github.com/ethanolivertroy/kevs-tui`
- **Main Framework**: Bubble Tea (TUI), Google ADK (Agent)
- **Purpose**: Interactive security vulnerability browser with AI-powered analysis

## Essential Commands

### Building
```bash
go build ./...                    # Build all packages
go build -o kev .                 # Build main binary
```

### Testing
```bash
go test ./...                     # Run all tests
go test -coverprofile=coverage.out -covermode=atomic ./...  # With coverage
```

### Linting
```bash
golangci-lint run                 # Run linters (v2.7.2)
```

### Running
```bash
go run .                          # Run TUI (KEV browser + agent sidebar)
go run . agent                    # Interactive agent chat only
go run . agent "Microsoft vulns"   # One-shot query
go run . serve                    # Start A2A server on port 8001
go run . serve --port 9000        # A2A server on custom port
```

### Environment Variables
```bash
# LLM Provider Selection
LLM_PROVIDER=gemini               # Options: gemini, vertex, ollama, openrouter (default: gemini)
LLM_MODEL=gemini-2.0-flash        # Model name

# Gemini
GEMINI_API_KEY=your-key

# Vertex AI
VERTEX_PROJECT=gcp-project-id
VERTEX_LOCATION=us-central1

# Ollama
OLLAMA_URL=http://localhost:11434

# OpenRouter
OPENROUTER_API_KEY=your-key
```

## Code Organization

```
.
├── main.go                      # Entry point, AppModel, TUI layout
├── cmd/                         # Subcommand handlers
│   ├── agent.go                 # Agent CLI mode
│   └── serve.go                 # A2A server mode
└── internal/                    # Application logic
    ├── tui/                     # Bubble Tea models (app.go, styles.go, keys.go)
    ├── model/                   # Data structures (Vulnerability, EPSS, CVSS)
    ├── api/                     # External API clients (KEV, EPSS, NVD)
    ├── agent/                   # KEVin AI agent (Google ADK integration)
    ├── llm/                     # LLM provider abstraction
    ├── chat/                    # Chat interface for agent
    ├── server/                  # A2A server implementation
    ├── grc/                     # GRC compliance tools (NIST 800-53, FedRAMP)
    ├── palette/                 # Command palette (Ctrl+K)
    └── export/                  # Export to JSON/CSV/Markdown
```

## Code Patterns

### Bubble Tea Architecture

Models must implement the three core methods:

```go
type Model struct {
    // State fields
}

func (m Model) Init() tea.Cmd {
    // Initialize and return initial commands
    return tea.Batch(cmd1, cmd2)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    // Handle messages and update state
    switch msg := msg.(type) {
    case tea.KeyMsg:
        // Handle key presses
    case tea.WindowSizeMsg:
        // Handle resize
    case CustomMsg:
        // Handle custom messages
    }
    return m, nil
}

func (m Model) View() string {
    // Return rendered string
}
```

### Message Passing

Custom messages for inter-component communication:

```go
type VulnsLoadedMsg struct {
    Vulns []model.Vulnerability
}

type ErrorMsg struct {
    Err error
}

// In Update():
case VulnsLoadedMsg:
    m.vulns = msg.Vulns
    return m, nil
```

### Error Handling Pattern

Always wrap errors with context:

```go
if err != nil {
    return nil, fmt.Errorf("failed to fetch data: %w", err)
}
```

### LLM Provider Abstraction

The `internal/llm` package provides a unified interface for multiple LLM providers:

```go
cfg := llm.ConfigFromEnv()
if err := cfg.Validate(); err != nil {
    return err
}
model, err := llm.NewModel(ctx, cfg)
```

Supported providers:
- `gemini` (default): Requires `GEMINI_API_KEY`
- `vertex`: Requires `VERTEX_PROJECT` and `VERTEX_LOCATION`
- `ollama`: Requires `OLLAMA_URL` (defaults to localhost:11434)
- `openrouter`: Requires `OPENROUTER_API_KEY`

## Naming Conventions

### Files and Packages
- Package names: lowercase, single word (`tui`, `model`, `api`)
- File names: lowercase, underscore_separated (`app_test.go`, `vulnerability.go`)
- Test files: `{name}_test.go` in same package as code

### Types and Functions
- Types: PascalCase (`Model`, `Vulnerability`, `AppState`)
- Functions: PascalCase if exported (`NewModel()`, `FetchVulns()`)
- Functions: camelCase if private (`applySortAndFilter()`, `calculateStats()`)

### Constants
- Constants: PascalCase or UPPER_SNAKE_CASE for constants
  - PascalCase: `SortByDateAdded`, `ViewList`
  - UPPER_SNAKE_CASE: `AgentPanelWidth`, `HeaderHeight`

### Messages
- Messages: PascalCase ending with `Msg` (`VulnsLoadedMsg`, `ErrorMsg`)

## Testing Approach

### Table-Driven Tests

Use table-driven tests for multiple test cases:

```go
func TestNVDURL(t *testing.T) {
    tests := []struct {
        name     string
        cveID    string
        expected string
    }{
        {"standard CVE", "CVE-2024-1234", "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
        {"older CVE", "CVE-2021-44228", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            v := Vulnerability{CVEID: tt.cveID}
            if got := v.NVDURL(); got != tt.expected {
                t.Errorf("NVDURL() = %v, want %v", got, tt.expected)
            }
        })
    }
}
```

### Test File Location

Place tests next to the code they test:
- `internal/model/vulnerability.go` → `internal/model/vulnerability_test.go`
- `internal/tui/app.go` → `internal/tui/app_test.go`

## Linting Configuration

Uses `golangci-lint` v2.7.2 with these enabled linters:
- `bodyclose`: Ensure HTTP response bodies are closed
- `errcheck`: Check for unchecked errors
- `gosec`: Security checks
- `misspell`: Spell checking
- `staticcheck`: Comprehensive static analysis

### Configured Exclusions
- `gosec`: G301 (directory permissions), G304 (file inclusion via variable), G306 (file permissions)
- `staticcheck`: QF* (quick fix suggestions), ST* (style rules like package comments), S1009 (nil check before len for readability)

Run: `golangci-lint run` (or CI runs it automatically)

## Key Dependencies

### TUI Framework
- `github.com/charmbracelet/bubbletea` - Core TUI framework
- `github.com/charmbracelet/bubbles` - UI components (list, help, spinner, viewport)
- `github.com/charmbracelet/lipgloss` - Styling
- `github.com/NimbleMarkets/ntcharts` - Chart rendering

### AI/Agent
- `google.golang.org/adk` - Google Agent Development Kit
- `google.golang.org/genai` - Google GenAI SDK

### Data Sources
- CISA KEV: https://github.com/cisagov/kev-data
- EPSS API: https://api.first.org/data/v1/epss
- NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0

## Important Gotchas

### TUI Layout (Crush-style)
The main TUI (`main.go`) uses a two-panel layout:
- **Left panel**: KEV browser (variable width, subtract AgentPanelWidth from total)
- **Right panel**: Agent sidebar (fixed width: 45 chars, hidden if compact mode)

Compact mode activates when `width < 100`.

### Mouse Throttling
Mouse events are throttled to 15ms to prevent performance issues:

```go
const MouseThrottleMs = 15

var lastMouseEvent time.Time

// In Update():
case tea.MouseMsg:
    now := time.Now()
    if now.Sub(lastMouseEvent) < MouseThrottleMs*time.Millisecond {
        return m, nil  // Skip this event
    }
    lastMouseEvent = now
```

### Message Routing
In the main TUI wrapper (`main.go`), messages are routed to the focused panel only to prevent flickering:

```go
// Route other messages to focused panel only (prevents flickering from spinner ticks)
if m.focusedPanel == PanelAgent && m.agentModel != nil && !m.compact {
    var cmd tea.Cmd
    m.agentModel, cmd = m.agentModel.Update(msg)
    return m, cmd
}
```

### Agent Initialization
The agent initializes lazily when `GEMINI_API_KEY` is set:

```go
// In Init():
if os.Getenv("GEMINI_API_KEY") != "" {
    cmds = append(cmds, m.initAgent())
}
```

### Async Data Fetching
Data fetching is done asynchronously via commands:

```go
func (m Model) fetchVulns() tea.Cmd {
    return func() tea.Msg {
        vulns, err := m.apiClient.FetchVulnerabilities()
        if err != nil {
            return ErrorMsg{Err: err}
        }
        return VulnsLoadedMsg{Vulns: vulns}
    }
}
```

### Error Resilience
Some failures shouldn't crash the app:
- EPSS fetch failures are handled gracefully (continues without EPSS data)
- CVSS fetch failures return empty data but don't prevent detail view display

### API Rate Limiting
EPSS API requests are chunked (100 CVEs per request) to avoid URL length issues:

```go
chunkSize := 100
for i := 0; i < len(cveIDs); i += chunkSize {
    end := i + chunkSize
    if end > len(cveIDs) {
        end = len(cveIDs)
    }
    chunk := cveIDs[i:end]
    // Fetch for this chunk...
}
```

### Environment Configuration
LLM provider must be configured via environment variables. The agent will not initialize without proper configuration.

### Subcommands
The application has multiple entry points:
- No args: Default TUI mode (browser + agent sidebar)
- `agent`: Agent chat mode (interactive or one-shot)
- `serve`: A2A server mode

## Git Workflow

### Branches
- Main branch: `main`
- Current development: `feature/kevin-agent-v2`

### Commits
Use conventional commits:
- `feat:` for new features
- `fix:` for bug fixes
- `refactor:` for code refactoring
- `test:` for test additions
- `docs:` for documentation

### CI/CD
- GitHub Actions on push to `main` and pull requests
- Runs: Build, Test, Lint, OSV Scanner, Scorecard
- Code coverage uploaded to Codecov

## Documentation Style

- Add comments to explain **why**, not **what** (code should be self-explanatory)
- Exported types/functions should have clear documentation
- Keep README.md up-to-date with usage examples
- AGENTS.md for AI agent guidance (this file)

## When Adding Features

1. **Model**: Add/update data structures in `internal/model/`
2. **API**: Add API client methods in `internal/api/` if needed
3. **TUI**: Update Bubble Tea models in `internal/tui/` (Update/View methods)
4. **Tests**: Add table-driven tests in `*_test.go` files
5. **Lint**: Run `golangci-lint run` and fix issues
6. **Test**: Run `go test ./...` and ensure all pass

## Common Tasks

### Add a new LLM provider
1. Create implementation in `internal/llm/{provider}.go`
2. Add case in `llm.NewModel()` in `provider.go`
3. Add config fields in `llm.Config` struct
4. Update `Config.Validate()` to check required env vars

### Add a new TUI view
1. Add view constant to `ViewState` enum in `internal/tui/app.go`
2. Add keyboard handler in `Update()` switch statement
3. Implement renderer method (e.g., `renderNewView()`)
4. Add to `View()` method switch

### Add a new agent tool
1. Implement tool function in `internal/agent/tools.go`
2. Register in `CreateTools()` function
3. Add to agent system instruction documentation

### Add new chart
1. Add to `ChartOption` slice in `NewModel()`
2. Implement render function in `internal/tui/charts.go`
3. Add handler in `Update()` for the chart view

### Add export format
1. Add to `ExportFormat` enum in `internal/tui/export.go`
2. Implement export function
3. Add to `exportOptions` slice in `NewModel()`
4. Handle in export menu switch statement
