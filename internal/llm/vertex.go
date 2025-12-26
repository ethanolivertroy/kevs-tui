package llm

import (
	"context"
	"fmt"

	"google.golang.org/adk/model"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/genai"
)

// NewVertexModel creates an ADK model using Vertex AI backend
// Requires Application Default Credentials (run `gcloud auth application-default login`)
func NewVertexModel(ctx context.Context, cfg Config) (model.LLM, error) {
	if cfg.VertexProject == "" {
		return nil, fmt.Errorf("VERTEX_PROJECT is required for Vertex AI provider")
	}
	if cfg.VertexLocation == "" {
		return nil, fmt.Errorf("VERTEX_LOCATION is required for Vertex AI provider")
	}

	modelName := cfg.Model
	if modelName == "" {
		modelName = "gemini-2.0-flash"
	}

	m, err := gemini.NewModel(ctx, modelName, &genai.ClientConfig{
		Project:  cfg.VertexProject,
		Location: cfg.VertexLocation,
		Backend:  genai.BackendVertexAI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Vertex AI model: %w", err)
	}

	return m, nil
}
