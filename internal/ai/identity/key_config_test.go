package identity

import (
	"context"
	"sync"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func TestKeyConfig_ApplyDefaults_Model(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	store.SetKeyConfig("key-1", &KeyConfig{
		DefaultModel: "gpt-4o-mini",
	})
	resolver := NewKeyConfigResolver(store)

	req := &ai.ChatCompletionRequest{}
	cfg, err := resolver.ApplyDefaults(context.Background(), "key-1", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
	if req.Model != "gpt-4o-mini" {
		t.Errorf("expected model gpt-4o-mini, got %q", req.Model)
	}
}

func TestKeyConfig_ApplyDefaults_Temperature(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	store.SetKeyConfig("key-1", &KeyConfig{
		DefaultParams: map[string]any{
			"temperature": 0.7,
			"top_p":       0.9,
		},
	})
	resolver := NewKeyConfigResolver(store)

	req := &ai.ChatCompletionRequest{}
	_, err := resolver.ApplyDefaults(context.Background(), "key-1", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Temperature == nil || *req.Temperature != 0.7 {
		t.Errorf("expected temperature 0.7, got %v", req.Temperature)
	}
	if req.TopP == nil || *req.TopP != 0.9 {
		t.Errorf("expected top_p 0.9, got %v", req.TopP)
	}
}

func TestKeyConfig_ApplyDefaults_MaxTokens(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	store.SetKeyConfig("key-1", &KeyConfig{
		DefaultParams: map[string]any{
			"max_tokens": 2000,
		},
		MaxTokens: 1000, // Hard cap
	})
	resolver := NewKeyConfigResolver(store)

	t.Run("default capped by hard limit", func(t *testing.T) {
		req := &ai.ChatCompletionRequest{}
		_, err := resolver.ApplyDefaults(context.Background(), "key-1", req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.MaxTokens == nil {
			t.Fatal("expected max_tokens to be set")
		}
		if *req.MaxTokens != 1000 {
			t.Errorf("expected max_tokens capped to 1000, got %d", *req.MaxTokens)
		}
	})

	t.Run("request value capped by hard limit", func(t *testing.T) {
		maxTok := 5000
		req := &ai.ChatCompletionRequest{
			MaxTokens: &maxTok,
		}
		_, err := resolver.ApplyDefaults(context.Background(), "key-1", req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if *req.MaxTokens != 1000 {
			t.Errorf("expected max_tokens capped to 1000, got %d", *req.MaxTokens)
		}
	})
}

func TestKeyConfig_ApplyDefaults_Tags(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	store.SetKeyConfig("key-1", &KeyConfig{
		Tags: map[string]string{
			"env":  "production",
			"team": "backend",
		},
	})
	resolver := NewKeyConfigResolver(store)

	t.Run("no request tags, all defaults applied", func(t *testing.T) {
		req := &ai.ChatCompletionRequest{}
		_, err := resolver.ApplyDefaults(context.Background(), "key-1", req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.SBTags["env"] != "production" {
			t.Errorf("expected env=production, got %q", req.SBTags["env"])
		}
		if req.SBTags["team"] != "backend" {
			t.Errorf("expected team=backend, got %q", req.SBTags["team"])
		}
	})

	t.Run("request tags take precedence", func(t *testing.T) {
		req := &ai.ChatCompletionRequest{
			SBTags: map[string]string{
				"env": "staging",
			},
		}
		_, err := resolver.ApplyDefaults(context.Background(), "key-1", req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.SBTags["env"] != "staging" {
			t.Errorf("expected env=staging (request precedence), got %q", req.SBTags["env"])
		}
		if req.SBTags["team"] != "backend" {
			t.Errorf("expected team=backend (from defaults), got %q", req.SBTags["team"])
		}
	})
}

func TestKeyConfig_ApplyDefaults_NoConfig(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	resolver := NewKeyConfigResolver(store)

	temp := 0.5
	req := &ai.ChatCompletionRequest{
		Model:       "gpt-4o",
		Temperature: &temp,
	}
	cfg, err := resolver.ApplyDefaults(context.Background(), "nonexistent-key", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config for nonexistent key")
	}
	if req.Model != "gpt-4o" {
		t.Errorf("model should be unchanged, got %q", req.Model)
	}
	if *req.Temperature != 0.5 {
		t.Errorf("temperature should be unchanged, got %f", *req.Temperature)
	}
}

func TestKeyConfig_ApplyDefaults_RequestPrecedence(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	store.SetKeyConfig("key-1", &KeyConfig{
		DefaultModel: "gpt-4o-mini",
		DefaultParams: map[string]any{
			"temperature": 0.3,
			"top_p":       0.8,
		},
	})
	resolver := NewKeyConfigResolver(store)

	temp := 0.9
	topP := 0.5
	req := &ai.ChatCompletionRequest{
		Model:       "gpt-4o",
		Temperature: &temp,
		TopP:        &topP,
	}
	_, err := resolver.ApplyDefaults(context.Background(), "key-1", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Model != "gpt-4o" {
		t.Errorf("expected request model gpt-4o preserved, got %q", req.Model)
	}
	if *req.Temperature != 0.9 {
		t.Errorf("expected request temperature 0.9 preserved, got %f", *req.Temperature)
	}
	if *req.TopP != 0.5 {
		t.Errorf("expected request top_p 0.5 preserved, got %f", *req.TopP)
	}
}

func TestKeyConfig_ValidateAccess_Allowed(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	store.SetKeyConfig("key-1", &KeyConfig{
		AllowedModels: []string{"gpt-4o", "gpt-4o-mini"},
	})
	resolver := NewKeyConfigResolver(store)

	err := resolver.ValidateAccess(context.Background(), "key-1", "gpt-4o")
	if err != nil {
		t.Errorf("expected access allowed, got error: %v", err)
	}
}

func TestKeyConfig_ValidateAccess_Blocked(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	store.SetKeyConfig("key-1", &KeyConfig{
		BlockedModels: []string{"gpt-4-turbo"},
	})
	resolver := NewKeyConfigResolver(store)

	err := resolver.ValidateAccess(context.Background(), "key-1", "gpt-4-turbo")
	if err == nil {
		t.Error("expected access denied for blocked model")
	}

	// Non-blocked model should be allowed.
	err = resolver.ValidateAccess(context.Background(), "key-1", "gpt-4o")
	if err != nil {
		t.Errorf("expected access allowed for non-blocked model, got: %v", err)
	}
}

func TestKeyConfig_ValidateAccess_NotInAllowed(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	store.SetKeyConfig("key-1", &KeyConfig{
		AllowedModels: []string{"gpt-4o", "gpt-4o-mini"},
	})
	resolver := NewKeyConfigResolver(store)

	err := resolver.ValidateAccess(context.Background(), "key-1", "claude-3-opus")
	if err == nil {
		t.Error("expected access denied for model not in allowed list")
	}
}

func TestKeyConfig_Store_CRUD(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	ctx := context.Background()

	// Create.
	store.SetKeyConfig("key-1", &KeyConfig{
		DefaultModel: "gpt-4o",
		Tags:         map[string]string{"env": "test"},
	})

	// Read.
	cfg, err := store.GetKeyConfig(ctx, "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
	if cfg.DefaultModel != "gpt-4o" {
		t.Errorf("expected gpt-4o, got %q", cfg.DefaultModel)
	}

	// Update.
	store.SetKeyConfig("key-1", &KeyConfig{
		DefaultModel: "gpt-4o-mini",
	})
	cfg, _ = store.GetKeyConfig(ctx, "key-1")
	if cfg.DefaultModel != "gpt-4o-mini" {
		t.Errorf("expected gpt-4o-mini after update, got %q", cfg.DefaultModel)
	}

	// Delete.
	store.DeleteKeyConfig("key-1")
	cfg, _ = store.GetKeyConfig(ctx, "key-1")
	if cfg != nil {
		t.Error("expected nil after delete")
	}
}

func TestKeyConfig_ConcurrentAccess(t *testing.T) {
	store := NewMemoryKeyConfigStore()
	resolver := NewKeyConfigResolver(store)
	ctx := context.Background()

	store.SetKeyConfig("key-1", &KeyConfig{
		DefaultModel: "gpt-4o",
		DefaultParams: map[string]any{
			"temperature": 0.5,
		},
		Tags: map[string]string{"env": "test"},
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &ai.ChatCompletionRequest{}
			_, err := resolver.ApplyDefaults(ctx, "key-1", req)
			if err != nil {
				t.Errorf("concurrent ApplyDefaults error: %v", err)
			}
		}()
	}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := resolver.ValidateAccess(ctx, "key-1", "gpt-4o")
			if err != nil {
				t.Errorf("concurrent ValidateAccess error: %v", err)
			}
		}()
	}

	wg.Wait()
}
