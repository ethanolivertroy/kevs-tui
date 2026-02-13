package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethanolivertroy/kevs-tui/internal/llm"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

// EventKind categorizes streaming events from the agent.
type EventKind int

const (
	EventText      EventKind = iota // Streaming text chunk
	EventToolStart                  // Tool call starting (name + params)
	EventToolDone                   // Tool call completed
	EventDone                       // Turn complete
	EventError                      // Error occurred
)

// AgentEvent is a structured event emitted during streaming agent execution.
// The chat UI consumes these to show real-time tool activity and text.
type AgentEvent struct {
	Kind     EventKind
	Text     string         // For EventText: the text chunk
	ToolName string         // For EventToolStart/EventToolDone: tool name
	Params   map[string]any // For EventToolStart: tool arguments
	Err      error          // For EventError
}

const (
	// SystemInstruction for KEVin
	SystemInstruction = `You are KEVin, a security expert for the CISA Known Exploited Vulnerabilities (KEV) catalog.

CRITICAL BEHAVIOR - Be action-oriented:
- When a user mentions ANY product, vendor, or keyword - IMMEDIATELY search for it
- Do NOT ask clarifying questions if you can make a reasonable assumption
- When in doubt, USE YOUR TOOLS FIRST, then explain the results
- If a search returns nothing, say so briefly and suggest alternatives

Examples of how to handle queries:
- "what happened to REACT?" → search_kevs(query="React") immediately
- "Microsoft stuff" → search_kevs(vendor="Microsoft") immediately
- "any ransomware CVEs?" → list_ransomware_cves() immediately
- "CVE-2024-1234" → get_cve_details(cve_id="CVE-2024-1234") immediately

Your KEV tools:
- search_kevs: Search by keyword, vendor, or product
- get_cve_details: Get detailed info about a specific CVE
- list_ransomware_cves: List CVEs used in ransomware campaigns
- list_overdue_cves: List CVEs past remediation due date
- get_stats: Get KEV catalog statistics
- export_report: Export to JSON/CSV/Markdown

Your GRC Compliance tools:
- map_cve_to_controls: Map a CVE to NIST 800-53, FedRAMP, or CIS Controls v8
- get_control_details: Get details about a specific security control (e.g., SI-2, RA-5 for NIST or 7.1, 10.1 for CIS)
- list_controls: List available security controls by family (NIST/FedRAMP) or implementation group (CIS)

Your Analytics tools:
- find_related_cves: Find CVEs related by CWE, vendor, or product
- get_vendor_risk_profile: Get comprehensive risk assessment for a vendor
- batch_analyze: Analyze multiple CVEs at once with prioritization
- analyze_cwe: Deep dive on a CWE with affected vendors and mitigations
- check_exploit_availability: Check for public exploits (GitHub PoCs, Nuclei templates)
- check_patch_status: Check for patches and vendor advisories
- analyze_trends: Analyze vulnerability trends over time

When presenting results:
- Lead with the data, keep explanations brief
- Include EPSS scores when available (higher = more likely exploited)
- Highlight ransomware association and overdue status
- Use markdown for clarity

When presenting GRC mappings:
- Explain why each control applies based on the rationale
- For NIST/FedRAMP: Highlight P1 (highest priority) controls and baseline levels
- For CIS: Note implementation group (IG1=basic hygiene, IG2=medium enterprise, IG3=large enterprise)
- Suggest remediation actions based on control requirements

Examples for GRC queries:
- "what controls apply to CVE-2024-1234?" → map_cve_to_controls immediately
- "map this CVE to CIS controls" → map_cve_to_controls with framework="cis"
- "explain SI-2" → get_control_details immediately
- "explain CIS control 7.1" → get_control_details with framework="cis"
- "show incident response controls" → list_controls with family filter
- "list CIS IG1 controls" → list_controls with framework="cis" and implementation_group=1

Context-aware queries:
When a message starts with [Context: User is viewing CVE-XXXX...]:
- The user is asking about that specific CVE
- Use the CVE ID from context for tool calls
- "this", "it", "the CVE", "this vulnerability" all refer to the context CVE
- Don't ask which CVE they mean - use the one from context
- The context includes EPSS score and due date status to help you prioritize advice

Remediation-focused queries (IMPORTANT):
When a user asks "what do I do?", "how do I fix?", "what should I do?", "what actions?", "help with this":
1. FIRST check for patches using check_patch_status
2. THEN check exploit availability using check_exploit_availability
3. Provide practical, actionable remediation steps:
   - Is a patch available? Link to the vendor advisory
   - Is there a public exploit? Emphasize urgency
   - Is it overdue? Note compliance deadline implications
   - What's the EPSS score? Contextualize the risk
4. Keep it brief and actionable - bullet points work well
5. Only mention controls/frameworks if the user specifically asks

Do NOT default to control mappings (map_cve_to_controls) for remediation questions.
Control mappings are for explicit requests like: "what controls apply?", "map to NIST", "show compliance mapping", "CIS controls"

Only redirect to KEV topics if the query is completely unrelated to security.`
)

// KEVAgent wraps the ADK agent with KEV-specific functionality
type KEVAgent struct {
	agent          agent.Agent
	runner         *runner.Runner
	sessionService session.Service
	// Session tracking for multi-turn conversations (protected by mu)
	mu         sync.Mutex
	userID     string
	sessionID  string
	hasSession bool
}

// New creates a new KEV agent using default LLM config from environment
func New(ctx context.Context) (*KEVAgent, error) {
	cfg := llm.ConfigFromEnv()
	return NewWithConfig(ctx, cfg)
}

// NewWithConfig creates a new KEV agent with the specified LLM config
func NewWithConfig(ctx context.Context, cfg llm.Config) (*KEVAgent, error) {
	// Validate config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create the LLM model
	model, err := llm.NewModel(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM model: %w", err)
	}

	// Create the KEV tools
	tools, err := CreateTools()
	if err != nil {
		return nil, fmt.Errorf("failed to create tools: %w", err)
	}

	// Create the GRC tools
	grcTools, err := CreateGRCTools()
	if err != nil {
		return nil, fmt.Errorf("failed to create GRC tools: %w", err)
	}
	tools = append(tools, grcTools...)

	// Create the Analytics tools
	analyticsTools, err := CreateAnalyticsTools()
	if err != nil {
		return nil, fmt.Errorf("failed to create analytics tools: %w", err)
	}
	tools = append(tools, analyticsTools...)

	// Create the LLM agent
	kevAgent, err := llmagent.New(llmagent.Config{
		Name:        "kev_agent",
		Description: "Security analyst assistant for querying the CISA KEV catalog with GRC control mapping",
		Model:       model,
		Instruction: SystemInstruction,
		Tools:       tools,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create agent: %w", err)
	}

	// Create session service
	sessionSvc := session.InMemoryService()

	// Create the runner
	r, err := runner.New(runner.Config{
		AppName:        "kevs-tui",
		Agent:          kevAgent,
		SessionService: sessionSvc,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create runner: %w", err)
	}

	return &KEVAgent{
		agent:          kevAgent,
		runner:         r,
		sessionService: sessionSvc,
	}, nil
}

// Agent returns the underlying ADK agent for use with launchers
func (a *KEVAgent) Agent() agent.Agent {
	return a.agent
}

// Query sends a query to the agent and returns the response.
// Each call creates a unique one-shot session for isolated queries.
func (a *KEVAgent) Query(ctx context.Context, query string) (string, error) {
	// Create a unique session for this one-shot query
	timestamp := time.Now().UnixNano()
	sessionResp, err := a.sessionService.Create(ctx, &session.CreateRequest{
		AppName:   "kevs-tui",
		UserID:    fmt.Sprintf("query-user-%d", timestamp),
		SessionID: fmt.Sprintf("query-session-%d", timestamp),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	// Create user message
	userMsg := &genai.Content{
		Role: "user",
		Parts: []*genai.Part{
			genai.NewPartFromText(query),
		},
	}

	// Run the agent
	var response strings.Builder
	for event, err := range a.runner.Run(ctx, sessionResp.Session.UserID(), sessionResp.Session.ID(), userMsg, agent.RunConfig{}) {
		if err != nil {
			return "", fmt.Errorf("agent error: %w", err)
		}

		// Extract text from the event
		if event.Content != nil {
			for _, part := range event.Content.Parts {
				if part.Text != "" {
					response.WriteString(part.Text)
				}
			}
		}
	}

	return response.String(), nil
}

// Chat sends a query to the agent using a persistent session for multi-turn conversations.
// The first call creates a session, subsequent calls reuse it for conversation context.
// This method is safe for concurrent use.
func (a *KEVAgent) Chat(ctx context.Context, query string) (string, error) {
	// Lock to safely access/modify session state
	a.mu.Lock()
	// Create session on first call
	if !a.hasSession {
		sessionResp, err := a.sessionService.Create(ctx, &session.CreateRequest{
			AppName:   "kevs-tui",
			UserID:    "chat-user",
			SessionID: fmt.Sprintf("chat-%d", time.Now().UnixNano()),
		})
		if err != nil {
			a.mu.Unlock()
			return "", fmt.Errorf("failed to create session: %w", err)
		}
		a.userID = sessionResp.Session.UserID()
		a.sessionID = sessionResp.Session.ID()
		a.hasSession = true
	}
	// Capture session IDs before unlocking
	userID := a.userID
	sessionID := a.sessionID
	a.mu.Unlock()

	// Create user message
	userMsg := &genai.Content{
		Role: "user",
		Parts: []*genai.Part{
			genai.NewPartFromText(query),
		},
	}

	// Run the agent with the persistent session (outside lock)
	var response strings.Builder
	for event, err := range a.runner.Run(ctx, userID, sessionID, userMsg, agent.RunConfig{}) {
		if err != nil {
			return "", fmt.Errorf("agent error: %w", err)
		}

		// Extract text from the event
		if event.Content != nil {
			for _, part := range event.Content.Parts {
				if part.Text != "" {
					response.WriteString(part.Text)
				}
			}
		}
	}

	return response.String(), nil
}

// ChatStream sends a query using a persistent session and emits structured events
// for real-time UI updates. The events channel is closed when the turn completes.
// Callers should range over the channel until it closes.
func (a *KEVAgent) ChatStream(ctx context.Context, query string, events chan<- AgentEvent) {
	defer close(events)

	// Ensure session exists (same logic as Chat)
	a.mu.Lock()
	if !a.hasSession {
		sessionResp, err := a.sessionService.Create(ctx, &session.CreateRequest{
			AppName:   "kevs-tui",
			UserID:    "chat-user",
			SessionID: fmt.Sprintf("chat-%d", time.Now().UnixNano()),
		})
		if err != nil {
			a.mu.Unlock()
			events <- AgentEvent{Kind: EventError, Err: fmt.Errorf("failed to create session: %w", err)}
			return
		}
		a.userID = sessionResp.Session.UserID()
		a.sessionID = sessionResp.Session.ID()
		a.hasSession = true
	}
	userID := a.userID
	sessionID := a.sessionID
	a.mu.Unlock()

	userMsg := &genai.Content{
		Role: "user",
		Parts: []*genai.Part{
			genai.NewPartFromText(query),
		},
	}

	// Run with SSE streaming to get partial text and tool call events
	for event, err := range a.runner.Run(ctx, userID, sessionID, userMsg, agent.RunConfig{
		StreamingMode: agent.StreamingModeSSE,
	}) {
		if err != nil {
			events <- AgentEvent{Kind: EventError, Err: fmt.Errorf("agent error: %w", err)}
			return
		}

		if event.Content == nil {
			continue
		}

		for _, part := range event.Content.Parts {
			// Tool call starting
			if part.FunctionCall != nil {
				events <- AgentEvent{
					Kind:     EventToolStart,
					ToolName: part.FunctionCall.Name,
					Params:   part.FunctionCall.Args,
				}
				continue
			}

			// Tool call completed
			if part.FunctionResponse != nil {
				events <- AgentEvent{
					Kind:     EventToolDone,
					ToolName: part.FunctionResponse.Name,
				}
				continue
			}

			// Text content
			if part.Text != "" {
				events <- AgentEvent{
					Kind: EventText,
					Text: part.Text,
				}
			}
		}

		// Turn complete
		if event.TurnComplete {
			events <- AgentEvent{Kind: EventDone}
			return
		}
	}

	// If we exit the loop without TurnComplete, still signal done
	events <- AgentEvent{Kind: EventDone}
}

// ClearSession clears the current chat session, starting fresh on next Chat() call.
// This method is safe for concurrent use.
func (a *KEVAgent) ClearSession() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hasSession = false
	a.userID = ""
	a.sessionID = ""
}
