package llm

import (
	"context"
	"fmt"
	"iter"
	"net/http"
	"net/url"

	"github.com/ollama/ollama/api"
	"google.golang.org/adk/model"
	"google.golang.org/genai"
)

// OllamaModel implements the ADK model.LLM interface using Ollama
type OllamaModel struct {
	client    *api.Client
	modelName string
}

// NewOllamaModel creates a new Ollama model
func NewOllamaModel(ctx context.Context, cfg Config) (model.LLM, error) {
	ollamaURL := cfg.OllamaURL
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	modelName := cfg.Model
	if modelName == "" {
		modelName = "llama3.2"
	}

	// Parse the URL
	u, err := url.Parse(ollamaURL)
	if err != nil {
		return nil, fmt.Errorf("invalid OLLAMA_URL: %w", err)
	}

	// Create client
	client := api.NewClient(u, http.DefaultClient)

	return &OllamaModel{
		client:    client,
		modelName: modelName,
	}, nil
}

// Name returns the model name
func (m *OllamaModel) Name() string {
	return m.modelName
}

// GenerateContent implements the ADK model.LLM interface
func (m *OllamaModel) GenerateContent(ctx context.Context, req *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		// Convert genai.Contents to Ollama messages
		messages := convertToOllamaMessages(req.Contents)

		// Build Ollama chat request
		chatReq := &api.ChatRequest{
			Model:    m.modelName,
			Messages: messages,
			Stream:   &stream,
		}

		// Add tools if available
		if len(req.Tools) > 0 {
			chatReq.Tools = convertToOllamaTools(req.Tools)
		}

		if stream {
			// Streaming mode
			var fullResponse string
			err := m.client.Chat(ctx, chatReq, func(resp api.ChatResponse) error {
				if resp.Message.Content != "" {
					fullResponse += resp.Message.Content

					llmResp := &model.LLMResponse{
						Content: &genai.Content{
							Role: "model",
							Parts: []*genai.Part{
								genai.NewPartFromText(resp.Message.Content),
							},
						},
						Partial:      !resp.Done,
						TurnComplete: resp.Done,
					}

					if !yield(llmResp, nil) {
						return fmt.Errorf("iteration stopped")
					}
				}

				// Handle tool calls
				if len(resp.Message.ToolCalls) > 0 {
					llmResp := convertToolCallsToResponse(resp.Message.ToolCalls)
					llmResp.TurnComplete = resp.Done
					if !yield(llmResp, nil) {
						return fmt.Errorf("iteration stopped")
					}
				}

				return nil
			})
			if err != nil {
				yield(nil, fmt.Errorf("Ollama chat error: %w", err))
				return
			}
		} else {
			// Non-streaming mode
			var finalResp api.ChatResponse
			err := m.client.Chat(ctx, chatReq, func(resp api.ChatResponse) error {
				finalResp = resp
				return nil
			})
			if err != nil {
				yield(nil, fmt.Errorf("Ollama chat error: %w", err))
				return
			}

			// Convert response
			llmResp := &model.LLMResponse{
				Content: &genai.Content{
					Role: "model",
					Parts: []*genai.Part{
						genai.NewPartFromText(finalResp.Message.Content),
					},
				},
				TurnComplete: true,
			}

			// Handle tool calls
			if len(finalResp.Message.ToolCalls) > 0 {
				llmResp = convertToolCallsToResponse(finalResp.Message.ToolCalls)
				llmResp.TurnComplete = true
			}

			yield(llmResp, nil)
		}
	}
}

// convertToOllamaMessages converts genai.Content to Ollama messages
func convertToOllamaMessages(contents []*genai.Content) []api.Message {
	var messages []api.Message

	for _, content := range contents {
		role := content.Role
		// Map genai roles to Ollama roles
		switch role {
		case "user":
			role = "user"
		case "model":
			role = "assistant"
		}

		var text string
		var toolCalls []api.ToolCall

		for _, part := range content.Parts {
			if part.Text != "" {
				text += part.Text
			}
			if part.FunctionCall != nil {
				toolCalls = append(toolCalls, api.ToolCall{
					Function: api.ToolCallFunction{
						Name:      part.FunctionCall.Name,
						Arguments: convertArgsToMap(part.FunctionCall.Args),
					},
				})
			}
		}

		msg := api.Message{
			Role:      role,
			Content:   text,
			ToolCalls: toolCalls,
		}

		messages = append(messages, msg)
	}

	return messages
}

// convertArgsToMap converts function call args
func convertArgsToMap(args map[string]any) api.ToolCallFunctionArguments {
	result := make(api.ToolCallFunctionArguments)
	for k, v := range args {
		result[k] = v
	}
	return result
}

// convertToOllamaTools converts ADK tools to Ollama tools
func convertToOllamaTools(tools map[string]any) []api.Tool {
	var ollamaTools []api.Tool

	for name, tool := range tools {
		// Try to extract tool description and parameters
		toolMap, ok := tool.(map[string]any)
		if !ok {
			continue
		}

		description, _ := toolMap["description"].(string)
		parameters, _ := toolMap["parameters"].(map[string]any)

		ollamaTools = append(ollamaTools, api.Tool{
			Type: "function",
			Function: api.ToolFunction{
				Name:        name,
				Description: description,
				Parameters: api.ToolFunctionParameters{
					Type:       "object",
					Properties: convertParameters(parameters),
				},
			},
		})
	}

	return ollamaTools
}

// convertParameters converts tool parameters to Ollama ToolProperty map
func convertParameters(params map[string]any) map[string]api.ToolProperty {
	result := make(map[string]api.ToolProperty)

	props, ok := params["properties"].(map[string]any)
	if !ok {
		return result
	}

	for name, prop := range props {
		propMap, ok := prop.(map[string]any)
		if !ok {
			continue
		}

		p := api.ToolProperty{
			Type:        api.PropertyType{"string"},
			Description: "",
		}

		if t, ok := propMap["type"].(string); ok {
			p.Type = api.PropertyType{t}
		}
		if d, ok := propMap["description"].(string); ok {
			p.Description = d
		}

		result[name] = p
	}

	return result
}

// convertToolCallsToResponse converts Ollama tool calls to ADK response
func convertToolCallsToResponse(toolCalls []api.ToolCall) *model.LLMResponse {
	var parts []*genai.Part

	for _, tc := range toolCalls {
		args := make(map[string]any)
		for k, v := range tc.Function.Arguments {
			args[k] = v
		}

		parts = append(parts, &genai.Part{
			FunctionCall: &genai.FunctionCall{
				Name: tc.Function.Name,
				Args: args,
			},
		})
	}

	return &model.LLMResponse{
		Content: &genai.Content{
			Role:  "model",
			Parts: parts,
		},
	}
}
