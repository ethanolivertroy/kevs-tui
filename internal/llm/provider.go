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
	Provider  string // "gemini", "vertex", "ollama", or "openrouter"
	Model     string // model name (e.g., "gemini-2.0-flash", "llama3.2", "anthropic/claude-sonnet-4")
	APIKey    string // for Gemini (GEMINI_API_KEY)
	OllamaURL string // for Ollama (default: http://localhost:11434)
	// Vertex AI fields
	VertexProject  string // GCP project ID (VERTEX_PROJECT)
	VertexLocation string // GCP region, e.g., "us-central1" (VERTEX_LOCATION)
	// OpenRouter fields
	OpenRouterAPIKey string // OpenRouter API key (OPENROUTER_API_KEY)
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
		case "openrouter":
			modelName = "anthropic/claude-sonnet-4"
		default:
			modelName = "gemini-2.0-flash"
		}
	}

	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	return Config{
		Provider:         provider,
		Model:            modelName,
		APIKey:           os.Getenv("GEMINI_API_KEY"),
		OllamaURL:        ollamaURL,
		VertexProject:    os.Getenv("VERTEX_PROJECT"),
		VertexLocation:   os.Getenv("VERTEX_LOCATION"),
		OpenRouterAPIKey: os.Getenv("OPENROUTER_API_KEY"),
	}
}

// NewModel creates an ADK-compatible model based on the config
func NewModel(ctx context.Context, cfg Config) (model.LLM, error) {
	switch cfg.Provider {
	case "gemini", "":
		return NewGeminiModel(ctx, cfg)
	case "vertex":
		return NewVertexModel(ctx, cfg)
	case "ollama":
		return NewOllamaModel(ctx, cfg)
	case "openrouter":
		return NewOpenRouterModel(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown LLM provider: %s (supported: gemini, vertex, ollama, openrouter)", cfg.Provider)
	}
}

// Validate checks if the config is valid for the selected provider
func (c Config) Validate() error {
	switch c.Provider {
	case "gemini", "":
		if c.APIKey == "" {
			return fmt.Errorf("GEMINI_API_KEY environment variable is required for Gemini provider")
		}
	case "vertex":
		if c.VertexProject == "" {
			return fmt.Errorf("VERTEX_PROJECT environment variable is required for Vertex AI provider")
		}
		if c.VertexLocation == "" {
			return fmt.Errorf("VERTEX_LOCATION environment variable is required for Vertex AI provider (e.g., us-central1)")
		}
	case "ollama":
		if c.OllamaURL == "" {
			return fmt.Errorf("OLLAMA_URL is required for Ollama provider")
		}
	case "openrouter":
		if c.OpenRouterAPIKey == "" {
			return fmt.Errorf("OPENROUTER_API_KEY environment variable is required for OpenRouter provider")
		}
	default:
		return fmt.Errorf("unknown LLM provider: %s", c.Provider)
	}
	return nil
}
