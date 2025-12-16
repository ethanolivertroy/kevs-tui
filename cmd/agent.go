package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ethanolivertroy/kevs-tui/internal/agent"
	"github.com/ethanolivertroy/kevs-tui/internal/chat"
)

// RunAgent runs the agent mode - interactive TUI if no args, one-shot if query provided
func RunAgent(args []string) error {
	// Check for API key early
	if os.Getenv("GEMINI_API_KEY") == "" {
		return fmt.Errorf("GEMINI_API_KEY environment variable is required for agent mode\n\nSet it with:\n  export GEMINI_API_KEY=your-api-key")
	}

	ctx := context.Background()

	// Create the agent
	fmt.Println("Initializing KEV agent...")
	kevAgent, err := agent.New(ctx)
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
