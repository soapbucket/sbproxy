package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewConfigurationManager(t *testing.T) {
	manager := NewConfigurationManager()
	if manager == nil {
		t.Fatal("manager is nil")
	}
	if manager.aiRegistry == nil {
		t.Error("AI registry not initialized")
	}
}

func TestLoadAIProvidersFromFileNotFound(t *testing.T) {
	manager := NewConfigurationManager()
	err := manager.LoadAIProvidersFromFile("/nonexistent/path/providers.yml")
	if err != nil {
		t.Errorf("unexpected error for missing file: %v", err)
	}
}

func TestLoadAIProvidersFromFileEmpty(t *testing.T) {
	manager := NewConfigurationManager()
	err := manager.LoadAIProvidersFromFile("")
	if err != nil {
		t.Errorf("unexpected error for empty path: %v", err)
	}
}

func TestLoadAIProvidersFromFileValid(t *testing.T) {
	// Create temporary file
	tmpDir := t.TempDir()
	filepath := filepath.Join(tmpDir, "providers.yml")

	content := `providers:
  - type: openai
    name: OpenAI
    hostnames:
      - api.openai.com
      - "*.openai.com"
    ports:
      - 443
    endpoints:
      - /v1/chat/completions
      - /v1/embeddings
  - type: anthropic
    name: Anthropic
    hostnames:
      - api.anthropic.com
    ports:
      - 443
    endpoints:
      - /v1/messages
`

	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	manager := NewConfigurationManager()
	err := manager.LoadAIProvidersFromFile(filepath)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify providers were loaded
	registry := manager.GetAIRegistry()
	_, found := registry.Get("openai")
	if !found {
		t.Error("OpenAI provider not found after loading")
	}

	_, found = registry.Get("anthropic")
	if !found {
		t.Error("Anthropic provider not found after loading")
	}
}

func TestLoadAIProvidersFromFileInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	filepath := filepath.Join(tmpDir, "providers.yml")

	content := `invalid: yaml: content: [[[`

	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	manager := NewConfigurationManager()
	err := manager.LoadAIProvidersFromFile(filepath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestGetAIRegistry(t *testing.T) {
	manager := NewConfigurationManager()
	registry := manager.GetAIRegistry()
	if registry == nil {
		t.Error("registry is nil")
	}
}

func TestLoadDefaults(t *testing.T) {
	manager := NewConfigurationManager()
	err := manager.LoadDefaults()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify defaults were loaded
	aiRegistry := manager.GetAIRegistry()
	_, found := aiRegistry.Get("openai")
	if !found {
		t.Error("OpenAI not in defaults")
	}

	_, found = aiRegistry.Get("anthropic")
	if !found {
		t.Error("Anthropic not in defaults")
	}

	openAIProvider, found := aiRegistry.Get("openai")
	if !found {
		t.Fatal("OpenAI not in defaults")
	}
	hasResponses := false
	for _, endpoint := range openAIProvider.Endpoints {
		if endpoint == "/v1/responses" {
			hasResponses = true
			break
		}
	}
	if !hasResponses {
		t.Error("OpenAI defaults should include /v1/responses")
	}
}

func TestIsLoaded(t *testing.T) {
	manager := NewConfigurationManager()

	// Initially not loaded
	if manager.IsLoaded() {
		t.Error("should not be loaded initially")
	}

	// After loading defaults
	manager.LoadDefaults()
	if !manager.IsLoaded() {
		t.Error("should be loaded after LoadDefaults")
	}
}

func TestReset(t *testing.T) {
	manager := NewConfigurationManager()

	// Load defaults
	manager.LoadDefaults()
	if !manager.IsLoaded() {
		t.Fatal("defaults not loaded")
	}

	// Reset
	manager.Reset()
	if manager.IsLoaded() {
		t.Error("should not be loaded after Reset")
	}

	// Verify registries are empty
	aiRegistry := manager.GetAIRegistry()
	if len(aiRegistry.GetAll()) > 0 {
		t.Error("AI registry not cleared after Reset")
	}
}

func TestGetStatistics(t *testing.T) {
	manager := NewConfigurationManager()

	// Before loading
	stats := manager.GetStatistics()
	if stats.ProvidersLoaded {
		t.Error("ProvidersLoaded should be false initially")
	}

	// After loading defaults
	manager.LoadDefaults()
	stats = manager.GetStatistics()

	if !stats.ProvidersLoaded {
		t.Error("should be loaded")
	}

	if stats.ProviderCount <= 0 {
		t.Error("provider count should be positive")
	}
}

func TestLoadMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create providers file
	providersPath := filepath.Join(tmpDir, "providers.yml")
	providersContent := `providers:
  - type: test-provider
    name: Test
    hostnames:
      - test.example.com
    ports:
      - 443
`

	if err := os.WriteFile(providersPath, []byte(providersContent), 0644); err != nil {
		t.Fatalf("failed to create providers file: %v", err)
	}

	manager := NewConfigurationManager()
	if err := manager.LoadAIProvidersFromFile(providersPath); err != nil {
		t.Fatalf("failed to load providers: %v", err)
	}

	// Verify loaded
	if !manager.IsLoaded() {
		t.Error("configuration not loaded")
	}

	stats := manager.GetStatistics()
	if !stats.ProvidersLoaded {
		t.Error("providers should be loaded")
	}
}
