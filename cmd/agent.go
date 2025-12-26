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

// RunAgent runs the agent mode - interactive TUI if no args, one-shot if query provided
func RunAgent(args []string) error {
	// Validate LLM config
	cfg := llm.ConfigFromEnv()
	if err := cfg.Validate(); err != nil {
		provider := cfg.Provider
		if provider == "" {
			provider = "gemini"
		}
		if provider == "gemini" {
			return fmt.Errorf("LLM configuration error: %w\n\nFor Gemini, set:\n  export GEMINI_API_KEY=your-api-key\n\nFor Ollama (local), set:\n  export LLM_PROVIDER=ollama", err)
		}
		return fmt.Errorf("LLM configuration error: %w", err)
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
