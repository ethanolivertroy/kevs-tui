package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethanolivertroy/kevs-tui/internal/llm"
	"github.com/ethanolivertroy/kevs-tui/internal/server"
)

// RunServe starts the A2A server for the KEVin agent
func RunServe(port int, host string) error {
	// Validate LLM config
	llmCfg := llm.ConfigFromEnv()
	if err := llmCfg.Validate(); err != nil {
		return err
	}

	// Create context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
	}()

	// Configure and start server
	cfg := server.A2AConfig{
		Port:      port,
		Host:      host,
		LLMConfig: llmCfg,
	}

	return server.RunA2AServer(ctx, cfg)
}
