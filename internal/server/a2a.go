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
	Host      string // Bind address (default "127.0.0.1" for localhost-only)
	LLMConfig llm.Config
}

// ConfigFromEnv creates an A2AConfig from environment variables
func ConfigFromEnv() A2AConfig {
	host := os.Getenv("A2A_HOST")
	if host == "" {
		host = "127.0.0.1" // Default to localhost-only for security
	}
	return A2AConfig{
		Port:      8001, // Default port
		Host:      host,
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

	// Default host to localhost if not set
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}

	// Create the web launcher with A2A support
	webLauncher := web.NewLauncher(a2a.NewLauncher())

	// Parse command line args (we override with our port and host)
	args := []string{
		"--port", fmt.Sprintf("%d", cfg.Port),
		"--host", cfg.Host,
	}
	if _, err := webLauncher.Parse(args); err != nil {
		return fmt.Errorf("failed to parse launcher args: %w", err)
	}

	// Print security warning if binding to non-localhost
	if cfg.Host != "127.0.0.1" && cfg.Host != "localhost" {
		fmt.Println("⚠️  SECURITY WARNING: Server binding to non-localhost address")
		fmt.Println("⚠️  This server has NO AUTHENTICATION - do not expose to untrusted networks")
		fmt.Println()
	}

	// Print startup info
	fmt.Printf("KEVin A2A Server starting on %s:%d\n", cfg.Host, cfg.Port)
	fmt.Printf("Agent card: http://%s:%d/.well-known/agent-card.json\n", cfg.Host, cfg.Port)
	fmt.Printf("A2A endpoint: http://%s:%d/a2a\n", cfg.Host, cfg.Port)
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
