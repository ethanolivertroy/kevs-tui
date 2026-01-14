package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"

	"google.golang.org/adk/model"
	"google.golang.org/genai"
)

const (
	openRouterBaseURL      = "https://openrouter.ai/api/v1"
	defaultOpenRouterModel = "anthropic/claude-sonnet-4"
)

// OpenRouterModel implements the ADK model.LLM interface using OpenRouter
type OpenRouterModel struct {
	apiKey    string
	modelName string
	client    *http.Client
}

// NewOpenRouterModel creates a new OpenRouter model
func NewOpenRouterModel(ctx context.Context, cfg Config) (model.LLM, error) {
	if cfg.OpenRouterAPIKey == "" {
		return nil, fmt.Errorf("OPENROUTER_API_KEY is required for OpenRouter provider")
	}

	modelName := cfg.Model
	if modelName == "" {
		modelName = defaultOpenRouterModel
	}

	return &OpenRouterModel{
		apiKey:    cfg.OpenRouterAPIKey,
		modelName: modelName,
		client:    &http.Client{},
	}, nil
}

// Name returns the model name
func (m *OpenRouterModel) Name() string {
	return m.modelName
}

// OpenRouter API types (OpenAI-compatible)
type openRouterRequest struct {
	Model    string              `json:"model"`
	Messages []openRouterMessage `json:"messages"`
	Tools    []openRouterTool    `json:"tools,omitempty"`
	Stream   bool                `json:"stream"`
}

type openRouterMessage struct {
	Role       string               `json:"role"`
	Content    string               `json:"content,omitempty"`
	ToolCalls  []openRouterToolCall `json:"tool_calls,omitempty"`
	ToolCallID string               `json:"tool_call_id,omitempty"`
}

type openRouterTool struct {
	Type     string             `json:"type"`
	Function openRouterFunction `json:"function"`
}

type openRouterFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type openRouterToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openRouterResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Index        int               `json:"index"`
		Message      openRouterMessage `json:"message"`
		Delta        openRouterMessage `json:"delta"`
		FinishReason string            `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// GenerateContent implements the ADK model.LLM interface
func (m *OpenRouterModel) GenerateContent(ctx context.Context, req *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		// Convert genai.Contents to OpenRouter messages
		messages := m.convertToOpenRouterMessages(req.Contents)

		// Build request
		orReq := openRouterRequest{
			Model:    m.modelName,
			Messages: messages,
			Stream:   stream,
		}

		// Add tools if available
		if len(req.Tools) > 0 {
			orReq.Tools = m.convertToOpenRouterTools(req.Tools)
		}

		reqBody, err := json.Marshal(orReq)
		if err != nil {
			yield(nil, fmt.Errorf("failed to marshal request: %w", err))
			return
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", openRouterBaseURL+"/chat/completions", bytes.NewReader(reqBody))
		if err != nil {
			yield(nil, fmt.Errorf("failed to create request: %w", err))
			return
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+m.apiKey)
		httpReq.Header.Set("HTTP-Referer", "https://github.com/ethanolivertroy/kevs-tui")
		httpReq.Header.Set("X-Title", "KEVs TUI")

		resp, err := m.client.Do(httpReq)
		if err != nil {
			yield(nil, fmt.Errorf("OpenRouter request failed: %w", err))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			yield(nil, fmt.Errorf("OpenRouter API error (status %d): %s", resp.StatusCode, string(body)))
			return
		}

		if stream {
			m.handleStreamingResponse(resp.Body, yield)
		} else {
			m.handleNonStreamingResponse(resp.Body, yield)
		}
	}
}

func (m *OpenRouterModel) handleStreamingResponse(body io.Reader, yield func(*model.LLMResponse, error) bool) {
	scanner := bufio.NewScanner(body)
	var accumulatedToolCalls []openRouterToolCall

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and non-data lines
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			// Final response
			if len(accumulatedToolCalls) > 0 {
				llmResp := m.convertToolCallsToResponse(accumulatedToolCalls)
				llmResp.TurnComplete = true
				yield(llmResp, nil)
			}
			return
		}

		var orResp openRouterResponse
		if err := json.Unmarshal([]byte(data), &orResp); err != nil {
			continue // Skip malformed chunks
		}

		if orResp.Error != nil {
			yield(nil, fmt.Errorf("OpenRouter error: %s", orResp.Error.Message))
			return
		}

		if len(orResp.Choices) == 0 {
			continue
		}

		choice := orResp.Choices[0]
		delta := choice.Delta

		// Handle text content
		if delta.Content != "" {
			llmResp := &model.LLMResponse{
				Content: &genai.Content{
					Role: "model",
					Parts: []*genai.Part{
						genai.NewPartFromText(delta.Content),
					},
				},
				Partial:      true,
				TurnComplete: false,
			}
			if !yield(llmResp, nil) {
				return
			}
		}

		// Accumulate tool calls (they come in chunks)
		for _, tc := range delta.ToolCalls {
			// Find or create tool call entry
			found := false
			for i := range accumulatedToolCalls {
				if accumulatedToolCalls[i].ID == tc.ID || (tc.ID == "" && i == len(accumulatedToolCalls)-1) {
					// Append to existing
					accumulatedToolCalls[i].Function.Arguments += tc.Function.Arguments
					if tc.Function.Name != "" {
						accumulatedToolCalls[i].Function.Name = tc.Function.Name
					}
					if tc.ID != "" {
						accumulatedToolCalls[i].ID = tc.ID
					}
					if tc.Type != "" {
						accumulatedToolCalls[i].Type = tc.Type
					}
					found = true
					break
				}
			}
			if !found {
				accumulatedToolCalls = append(accumulatedToolCalls, tc)
			}
		}

		// Check for finish
		if choice.FinishReason == "stop" || choice.FinishReason == "tool_calls" {
			if len(accumulatedToolCalls) > 0 {
				llmResp := m.convertToolCallsToResponse(accumulatedToolCalls)
				llmResp.TurnComplete = true
				yield(llmResp, nil)
			} else {
				// Send final empty response to signal completion
				llmResp := &model.LLMResponse{
					Content: &genai.Content{
						Role:  "model",
						Parts: []*genai.Part{},
					},
					TurnComplete: true,
				}
				yield(llmResp, nil)
			}
			return
		}
	}

	if err := scanner.Err(); err != nil {
		yield(nil, fmt.Errorf("error reading stream: %w", err))
	}
}

func (m *OpenRouterModel) handleNonStreamingResponse(body io.Reader, yield func(*model.LLMResponse, error) bool) {
	var orResp openRouterResponse
	if err := json.NewDecoder(body).Decode(&orResp); err != nil {
		yield(nil, fmt.Errorf("failed to decode response: %w", err))
		return
	}

	if orResp.Error != nil {
		yield(nil, fmt.Errorf("OpenRouter error: %s", orResp.Error.Message))
		return
	}

	if len(orResp.Choices) == 0 {
		yield(nil, fmt.Errorf("no choices in response"))
		return
	}

	choice := orResp.Choices[0]
	msg := choice.Message

	// Handle tool calls
	if len(msg.ToolCalls) > 0 {
		llmResp := m.convertToolCallsToResponse(msg.ToolCalls)
		llmResp.TurnComplete = true
		yield(llmResp, nil)
		return
	}

	// Handle text response
	llmResp := &model.LLMResponse{
		Content: &genai.Content{
			Role: "model",
			Parts: []*genai.Part{
				genai.NewPartFromText(msg.Content),
			},
		},
		TurnComplete: true,
	}
	yield(llmResp, nil)
}

func (m *OpenRouterModel) convertToOpenRouterMessages(contents []*genai.Content) []openRouterMessage {
	var messages []openRouterMessage

	for _, content := range contents {
		role := content.Role
		switch role {
		case "model":
			role = "assistant"
		case "user":
			role = "user"
		case "system":
			role = "system"
		}

		var text string
		var toolCalls []openRouterToolCall

		for _, part := range content.Parts {
			if part.Text != "" {
				text += part.Text
			}
			if part.FunctionCall != nil {
				argsJSON, _ := json.Marshal(part.FunctionCall.Args)
				toolCalls = append(toolCalls, openRouterToolCall{
					ID:   fmt.Sprintf("call_%s", part.FunctionCall.Name),
					Type: "function",
					Function: struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					}{
						Name:      part.FunctionCall.Name,
						Arguments: string(argsJSON),
					},
				})
			}
			if part.FunctionResponse != nil {
				// Function response becomes a tool message
				responseJSON, _ := json.Marshal(part.FunctionResponse.Response)
				messages = append(messages, openRouterMessage{
					Role:       "tool",
					Content:    string(responseJSON),
					ToolCallID: fmt.Sprintf("call_%s", part.FunctionResponse.Name),
				})
				continue
			}
		}

		if text != "" || len(toolCalls) > 0 {
			msg := openRouterMessage{
				Role:      role,
				Content:   text,
				ToolCalls: toolCalls,
			}
			messages = append(messages, msg)
		}
	}

	return messages
}

func (m *OpenRouterModel) convertToOpenRouterTools(tools map[string]any) []openRouterTool {
	var orTools []openRouterTool

	for name, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if !ok {
			continue
		}

		description, _ := toolMap["description"].(string)
		parameters, _ := toolMap["parameters"].(map[string]any)

		paramsJSON, _ := json.Marshal(parameters)

		orTools = append(orTools, openRouterTool{
			Type: "function",
			Function: openRouterFunction{
				Name:        name,
				Description: description,
				Parameters:  paramsJSON,
			},
		})
	}

	return orTools
}

func (m *OpenRouterModel) convertToolCallsToResponse(toolCalls []openRouterToolCall) *model.LLMResponse {
	var parts []*genai.Part

	for _, tc := range toolCalls {
		var args map[string]any
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
			args = make(map[string]any)
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
