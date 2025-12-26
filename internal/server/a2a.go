// Package server provides the A2A server for KEVin agent
package server

import (
	"context"
	"fmt"
	"os"

	"github.com/ethanolivertroy/kevs-tui/internal/agent"
	"github.com/ethanolivertroy/kevs-tui/internal/llm"
	adkagent "google.golang.org/adk/agent"
	"google.golang.org/adk/cmd/launcher"
	"google.golang.org/adk/cmd/launcher/web"
	"google.golang.org/adk/cmd/launcher/web/a2a"
	"google.golang.org/adk/session"
)

// A2AConfig holds configuration for the A2A server
type A2AConfig struct {
	Port      int
	LLMConfig llm.Config
}

// ConfigFromEnv creates an A2AConfig from environment variables
func ConfigFromEnv() A2AConfig {
	return A2AConfig{
		Port:      8001, // Default port
		LLMConfig: llm.ConfigFromEnv(),
	}
}

// RunA2AServer starts the KEVin agent as an A2A server
func RunA2AServer(ctx context.Context, cfg A2AConfig) error {
	// Validate LLM config
	if err := cfg.LLMConfig.Validate(); err != nil {
		return fmt.Errorf("invalid LLM config: %w", err)
	}

	// Create the KEVin agent
	kevAgent, err := agent.NewWithConfig(ctx, cfg.LLMConfig)
	if err != nil {
		return fmt.Errorf("failed to create KEVin agent: %w", err)
	}

	// Get the underlying ADK agent
	adkAgent := kevAgent.Agent()

	// Create the web launcher with A2A support
	webLauncher := web.NewLauncher(a2a.NewLauncher())

	// Parse command line args (we override with our port)
	args := []string{
		"--port", fmt.Sprintf("%d", cfg.Port),
	}
	if _, err := webLauncher.Parse(args); err != nil {
		return fmt.Errorf("failed to parse launcher args: %w", err)
	}

	// Print startup info
	fmt.Printf("KEVin A2A Server starting on port %d\n", cfg.Port)
	fmt.Printf("Agent card: http://localhost:%d/.well-known/agent-card.json\n", cfg.Port)
	fmt.Printf("A2A endpoint: http://localhost:%d/a2a\n", cfg.Port)
	fmt.Printf("LLM Provider: %s (%s)\n", cfg.LLMConfig.Provider, cfg.LLMConfig.Model)
	fmt.Println()

	// Run the launcher
	launcherConfig := &launcher.Config{
		AgentLoader:    adkagent.NewSingleLoader(adkAgent),
		SessionService: session.InMemoryService(),
	}

	return webLauncher.Run(ctx, launcherConfig)
}

// GetPort returns the server port from environment or default
func GetPort() int {
	portStr := os.Getenv("A2A_PORT")
	if portStr == "" {
		return 8001
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if port <= 0 {
		return 8001
	}
	return port
}
