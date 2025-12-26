package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ethanolivertroy/kevs-tui/internal/llm"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

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
- map_cve_to_controls: Map a CVE to NIST 800-53 or FedRAMP controls
- get_control_details: Get details about a specific security control (e.g., SI-2, RA-5)
- list_controls: List available security controls by family

When presenting results:
- Lead with the data, keep explanations brief
- Include EPSS scores when available (higher = more likely exploited)
- Highlight ransomware association and overdue status
- Use markdown for clarity

When presenting GRC mappings:
- Explain why each control applies based on the rationale
- Highlight P1 (highest priority) controls
- Note FedRAMP baseline levels when relevant
- Suggest remediation actions based on control requirements

Examples for GRC queries:
- "what controls apply to CVE-2024-1234?" → map_cve_to_controls immediately
- "explain SI-2" → get_control_details immediately
- "show incident response controls" → list_controls with family filter

Only redirect to KEV topics if the query is completely unrelated to security.`
)

// KEVAgent wraps the ADK agent with KEV-specific functionality
type KEVAgent struct {
	agent          agent.Agent
	runner         *runner.Runner
	sessionService session.Service
	// Session tracking for multi-turn conversations
	userID    string
	sessionID string
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

// Query sends a query to the agent and returns the response
func (a *KEVAgent) Query(ctx context.Context, query string) (string, error) {
	// Create a session for this query
	sessionResp, err := a.sessionService.Create(ctx, &session.CreateRequest{
		AppName:   "kevs-tui",
		UserID:    "user",
		SessionID: "session",
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
func (a *KEVAgent) Chat(ctx context.Context, query string) (string, error) {
	// Create session on first call
	if !a.hasSession {
		sessionResp, err := a.sessionService.Create(ctx, &session.CreateRequest{
			AppName:   "kevs-tui",
			UserID:    "chat-user",
			SessionID: fmt.Sprintf("chat-%d", time.Now().UnixNano()),
		})
		if err != nil {
			return "", fmt.Errorf("failed to create session: %w", err)
		}
		a.userID = sessionResp.Session.UserID()
		a.sessionID = sessionResp.Session.ID()
		a.hasSession = true
	}

	// Create user message
	userMsg := &genai.Content{
		Role: "user",
		Parts: []*genai.Part{
			genai.NewPartFromText(query),
		},
	}

	// Run the agent with the persistent session
	var response strings.Builder
	for event, err := range a.runner.Run(ctx, a.userID, a.sessionID, userMsg, agent.RunConfig{}) {
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

// ClearSession clears the current chat session, starting fresh on next Chat() call
func (a *KEVAgent) ClearSession() {
	a.hasSession = false
	a.userID = ""
	a.sessionID = ""
}
