// Package llm provides LLM provider abstraction for KEVin agent
package llm

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/adk/model"
)

// Config holds LLM configuration
type Config struct {
	Provider  string // "gemini" or "ollama"
	Model     string // model name (e.g., "gemini-2.0-flash", "llama3.2")
	APIKey    string // for Gemini (GEMINI_API_KEY)
	OllamaURL string // for Ollama (default: http://localhost:11434)
}

// ConfigFromEnv creates a Config from environment variables
func ConfigFromEnv() Config {
	provider := os.Getenv("LLM_PROVIDER")
	if provider == "" {
		provider = "gemini" // default
	}

	modelName := os.Getenv("LLM_MODEL")
	if modelName == "" {
		switch provider {
		case "ollama":
			modelName = "llama3.2"
		default:
			modelName = "gemini-2.0-flash"
		}
	}

	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	return Config{
		Provider:  provider,
		Model:     modelName,
		APIKey:    os.Getenv("GEMINI_API_KEY"),
		OllamaURL: ollamaURL,
	}
}

// NewModel creates an ADK-compatible model based on the config
func NewModel(ctx context.Context, cfg Config) (model.LLM, error) {
	switch cfg.Provider {
	case "gemini", "":
		return NewGeminiModel(ctx, cfg)
	case "ollama":
		return NewOllamaModel(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown LLM provider: %s (supported: gemini, ollama)", cfg.Provider)
	}
}

// Validate checks if the config is valid for the selected provider
func (c Config) Validate() error {
	switch c.Provider {
	case "gemini", "":
		if c.APIKey == "" {
			return fmt.Errorf("GEMINI_API_KEY environment variable is required for Gemini provider")
		}
	case "ollama":
		if c.OllamaURL == "" {
			return fmt.Errorf("OLLAMA_URL is required for Ollama provider")
		}
	default:
		return fmt.Errorf("unknown LLM provider: %s", c.Provider)
	}
	return nil
}
