package llm

import (
	"context"
	"fmt"

	"google.golang.org/adk/model"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/genai"
)

// NewGeminiModel creates an ADK Gemini model
func NewGeminiModel(ctx context.Context, cfg Config) (model.LLM, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY is required for Gemini provider")
	}

	modelName := cfg.Model
	if modelName == "" {
		modelName = "gemini-2.0-flash"
	}

	m, err := gemini.NewModel(ctx, modelName, &genai.ClientConfig{
		APIKey: cfg.APIKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini model: %w", err)
	}

	return m, nil
}
