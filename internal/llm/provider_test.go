package llm

import (
	"os"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "gemini without API key",
			config:  Config{Provider: "gemini"},
			wantErr: true,
			errMsg:  "GEMINI_API_KEY",
		},
		{
			name:    "gemini with API key",
			config:  Config{Provider: "gemini", APIKey: "test-key"},
			wantErr: false,
		},
		{
			name:    "empty provider defaults to gemini",
			config:  Config{Provider: "", APIKey: "test-key"},
			wantErr: false,
		},
		{
			name:    "vertex without project",
			config:  Config{Provider: "vertex"},
			wantErr: true,
			errMsg:  "VERTEX_PROJECT",
		},
		{
			name:    "vertex without location",
			config:  Config{Provider: "vertex", VertexProject: "my-project"},
			wantErr: true,
			errMsg:  "VERTEX_LOCATION",
		},
		{
			name: "vertex with all fields",
			config: Config{
				Provider:       "vertex",
				VertexProject:  "my-project",
				VertexLocation: "us-central1",
			},
			wantErr: false,
		},
		{
			name:    "ollama without URL",
			config:  Config{Provider: "ollama"},
			wantErr: true,
			errMsg:  "OLLAMA_URL",
		},
		{
			name:    "ollama with URL",
			config:  Config{Provider: "ollama", OllamaURL: "http://localhost:11434"},
			wantErr: false,
		},
		{
			name:    "openrouter without API key",
			config:  Config{Provider: "openrouter"},
			wantErr: true,
			errMsg:  "OPENROUTER_API_KEY",
		},
		{
			name:    "openrouter with API key",
			config:  Config{Provider: "openrouter", OpenRouterAPIKey: "test-key"},
			wantErr: false,
		},
		{
			name:    "unknown provider",
			config:  Config{Provider: "unknown"},
			wantErr: true,
			errMsg:  "unknown LLM provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigFromEnv(t *testing.T) {
	// Save original env
	origProvider := os.Getenv("LLM_PROVIDER")
	origModel := os.Getenv("LLM_MODEL")
	origAPIKey := os.Getenv("GEMINI_API_KEY")
	origOllamaURL := os.Getenv("OLLAMA_URL")
	origVertexProject := os.Getenv("VERTEX_PROJECT")
	origVertexLocation := os.Getenv("VERTEX_LOCATION")
	origOpenRouterKey := os.Getenv("OPENROUTER_API_KEY")

	// Restore after test
	defer func() {
		os.Setenv("LLM_PROVIDER", origProvider)
		os.Setenv("LLM_MODEL", origModel)
		os.Setenv("GEMINI_API_KEY", origAPIKey)
		os.Setenv("OLLAMA_URL", origOllamaURL)
		os.Setenv("VERTEX_PROJECT", origVertexProject)
		os.Setenv("VERTEX_LOCATION", origVertexLocation)
		os.Setenv("OPENROUTER_API_KEY", origOpenRouterKey)
	}()

	t.Run("default provider is gemini", func(t *testing.T) {
		os.Unsetenv("LLM_PROVIDER")
		os.Unsetenv("LLM_MODEL")
		cfg := ConfigFromEnv()
		if cfg.Provider != "gemini" {
			t.Errorf("Provider = %q, want gemini", cfg.Provider)
		}
		if cfg.Model != "gemini-2.0-flash" {
			t.Errorf("Model = %q, want gemini-2.0-flash", cfg.Model)
		}
	})

	t.Run("ollama default model", func(t *testing.T) {
		os.Setenv("LLM_PROVIDER", "ollama")
		os.Unsetenv("LLM_MODEL")
		cfg := ConfigFromEnv()
		if cfg.Model != "llama3.2" {
			t.Errorf("Model = %q, want llama3.2", cfg.Model)
		}
	})

	t.Run("openrouter default model", func(t *testing.T) {
		os.Setenv("LLM_PROVIDER", "openrouter")
		os.Unsetenv("LLM_MODEL")
		cfg := ConfigFromEnv()
		if cfg.Model != "anthropic/claude-sonnet-4" {
			t.Errorf("Model = %q, want anthropic/claude-sonnet-4", cfg.Model)
		}
	})

	t.Run("custom model", func(t *testing.T) {
		os.Setenv("LLM_PROVIDER", "gemini")
		os.Setenv("LLM_MODEL", "gemini-1.5-pro")
		cfg := ConfigFromEnv()
		if cfg.Model != "gemini-1.5-pro" {
			t.Errorf("Model = %q, want gemini-1.5-pro", cfg.Model)
		}
	})

	t.Run("default ollama URL", func(t *testing.T) {
		os.Unsetenv("OLLAMA_URL")
		cfg := ConfigFromEnv()
		if cfg.OllamaURL != "http://localhost:11434" {
			t.Errorf("OllamaURL = %q, want http://localhost:11434", cfg.OllamaURL)
		}
	})

	t.Run("reads all env vars", func(t *testing.T) {
		os.Setenv("LLM_PROVIDER", "vertex")
		os.Setenv("GEMINI_API_KEY", "gemini-key")
		os.Setenv("VERTEX_PROJECT", "my-project")
		os.Setenv("VERTEX_LOCATION", "us-east1")
		os.Setenv("OPENROUTER_API_KEY", "openrouter-key")
		os.Setenv("OLLAMA_URL", "http://custom:11434")

		cfg := ConfigFromEnv()

		if cfg.APIKey != "gemini-key" {
			t.Errorf("APIKey = %q, want gemini-key", cfg.APIKey)
		}
		if cfg.VertexProject != "my-project" {
			t.Errorf("VertexProject = %q, want my-project", cfg.VertexProject)
		}
		if cfg.VertexLocation != "us-east1" {
			t.Errorf("VertexLocation = %q, want us-east1", cfg.VertexLocation)
		}
		if cfg.OpenRouterAPIKey != "openrouter-key" {
			t.Errorf("OpenRouterAPIKey = %q, want openrouter-key", cfg.OpenRouterAPIKey)
		}
		if cfg.OllamaURL != "http://custom:11434" {
			t.Errorf("OllamaURL = %q, want http://custom:11434", cfg.OllamaURL)
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
