package cmd

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ethanolivertroy/kevs-tui/internal/agent"
	"github.com/ethanolivertroy/kevs-tui/internal/chat"
	"github.com/ethanolivertroy/kevs-tui/internal/llm"
)

// getProviderSetupHelp returns setup instructions for the specified LLM provider
func getProviderSetupHelp(provider string) string {
	switch provider {
	case "gemini", "":
		return `For Gemini (default), set:
  export GEMINI_API_KEY=your-api-key

For Ollama (local), set:
  export LLM_PROVIDER=ollama
  ollama serve`
	case "vertex":
		return `For Vertex AI, set:
  export LLM_PROVIDER=vertex
  export VERTEX_PROJECT=your-gcp-project
  export VERTEX_LOCATION=us-central1`
	case "ollama":
		return `For Ollama, ensure the server is running:
  ollama serve

Optionally set custom URL:
  export OLLAMA_URL=http://localhost:11434`
	case "openrouter":
		return `For OpenRouter, set:
  export LLM_PROVIDER=openrouter
  export OPENROUTER_API_KEY=your-api-key`
	default:
		return `Configure LLM_PROVIDER and required credentials.
Supported providers: gemini, vertex, ollama, openrouter`
	}
}

// RunAgent runs the agent mode - interactive TUI if no args, one-shot if query provided
func RunAgent(args []string) error {
	// Validate LLM config
	cfg := llm.ConfigFromEnv()
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("LLM configuration error: %w\n\n%s", err, getProviderSetupHelp(cfg.Provider))
	}

	ctx := context.Background()

	// Create the agent
	fmt.Printf("Initializing KEVin agent (%s/%s)...\n", cfg.Provider, cfg.Model)
	kevAgent, err := agent.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize agent: %w", err)
	}

	// If args provided, run one-shot query (no TUI)
	if len(args) > 0 {
		query := strings.Join(args, " ")
		if query == "" {
			return fmt.Errorf("query cannot be empty")
		}
		fmt.Printf("Query: %s\n\n", query)
		response, err := kevAgent.Query(ctx, query)
		if err != nil {
			return fmt.Errorf("query failed: %w", err)
		}
		fmt.Println(response)
		return nil
	}

	// Interactive mode - use Bubble Tea TUI
	model := chat.NewModel(ctx, kevAgent)
	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
