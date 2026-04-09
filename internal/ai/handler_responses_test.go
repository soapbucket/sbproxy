package ai

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

// responseMockCacher implements store.Cacher for testing the responses cache.
type responseMockCacher struct {
	data map[string]map[string][]byte
}

func newResponseMockCacher() *responseMockCacher {
	return &responseMockCacher{data: make(map[string]map[string][]byte)}
}

func (m *responseMockCacher) Get(_ context.Context, ns, key string) (io.Reader, error) {
	if bucket, ok := m.data[ns]; ok {
		if v, ok := bucket[key]; ok {
			return bytes.NewReader(v), nil
		}
	}
	return nil, nil
}

func (m *responseMockCacher) Put(_ context.Context, ns, key string, r io.Reader) error {
	data, _ := io.ReadAll(r)
	if m.data[ns] == nil {
		m.data[ns] = make(map[string][]byte)
	}
	m.data[ns][key] = data
	return nil
}

func (m *responseMockCacher) PutWithExpires(_ context.Context, ns, key string, r io.Reader, _ time.Duration) error {
	return m.Put(context.Background(), ns, key, r)
}

func (m *responseMockCacher) Delete(_ context.Context, ns, key string) error {
	if bucket, ok := m.data[ns]; ok {
		delete(bucket, key)
	}
	return nil
}

func (m *responseMockCacher) ListKeys(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}

func (m *responseMockCacher) Increment(_ context.Context, _, _ string, _ int64) (int64, error) {
	return 0, nil
}

func (m *responseMockCacher) IncrementWithExpires(_ context.Context, _, _ string, _ int64, _ time.Duration) (int64, error) {
	return 0, nil
}

func (m *responseMockCacher) DeleteByPattern(_ context.Context, _, _ string) error {
	return nil
}

func (m *responseMockCacher) Driver() string { return "mock" }
func (m *responseMockCacher) Close() error   { return nil }

func TestResponseContextCache_StoreAndLoad(t *testing.T) {
	mc := newResponseMockCacher()
	cache := NewResponseContextCache(mc)

	msgs := []Message{
		mustTextMessage("user", "Hello"),
		mustTextMessage("assistant", "Hi there!"),
	}

	ctx := context.Background()
	if err := cache.StoreContext(ctx, "resp_123", msgs); err != nil {
		t.Fatalf("StoreContext failed: %v", err)
	}

	loaded, err := cache.LoadContext(ctx, "resp_123")
	if err != nil {
		t.Fatalf("LoadContext failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(loaded))
	}
	if loaded[0].Role != "user" {
		t.Errorf("expected role 'user', got %q", loaded[0].Role)
	}
	if loaded[1].ContentString() != "Hi there!" {
		t.Errorf("expected content 'Hi there!', got %q", loaded[1].ContentString())
	}
}

func TestResponseContextCache_LoadMissing(t *testing.T) {
	mc := newResponseMockCacher()
	cache := NewResponseContextCache(mc)

	msgs, err := cache.LoadContext(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgs != nil {
		t.Errorf("expected nil messages for missing key, got %d", len(msgs))
	}
}

func TestResponsesBridge_SimpleInput(t *testing.T) {
	mc := newResponseMockCacher()
	cache := NewResponseContextCache(mc)
	store := NewMemoryResponseStore(100, time.Hour)
	defer store.Close()

	bridge := NewResponsesBridge(cache, store)

	input, _ := json.Marshal("What is Go?")
	req := &CreateResponseRequest{
		Model: "gpt-4o",
		Input: input,
	}

	chatReq, err := bridge.ToChatCompletion(context.Background(), req)
	if err != nil {
		t.Fatalf("ToChatCompletion failed: %v", err)
	}

	if chatReq.Model != "gpt-4o" {
		t.Errorf("expected model gpt-4o, got %s", chatReq.Model)
	}
	if len(chatReq.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(chatReq.Messages))
	}
	if chatReq.Messages[0].Role != "user" {
		t.Errorf("expected role 'user', got %q", chatReq.Messages[0].Role)
	}
	if chatReq.Messages[0].ContentString() != "What is Go?" {
		t.Errorf("expected content 'What is Go?', got %q", chatReq.Messages[0].ContentString())
	}
}

func TestResponsesBridge_MultiTurn(t *testing.T) {
	mc := newResponseMockCacher()
	cache := NewResponseContextCache(mc)
	store := NewMemoryResponseStore(100, time.Hour)
	defer store.Close()

	bridge := NewResponsesBridge(cache, store)
	ctx := context.Background()

	// Store a conversation context for a previous response
	prevMsgs := []Message{
		mustTextMessage("user", "What is 2+2?"),
		mustTextMessage("assistant", "It is 4."),
	}
	if err := cache.StoreContext(ctx, "resp_prev", prevMsgs); err != nil {
		t.Fatalf("StoreContext failed: %v", err)
	}

	// Make a follow-up request referencing the previous response
	input, _ := json.Marshal("And 3+3?")
	req := &CreateResponseRequest{
		Model:              "gpt-4o",
		Input:              input,
		PreviousResponseID: "resp_prev",
	}

	chatReq, err := bridge.ToChatCompletion(ctx, req)
	if err != nil {
		t.Fatalf("ToChatCompletion failed: %v", err)
	}

	// Should have: user("What is 2+2?") + assistant("It is 4.") + user("And 3+3?")
	if len(chatReq.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(chatReq.Messages))
	}
	if chatReq.Messages[0].ContentString() != "What is 2+2?" {
		t.Errorf("expected first message 'What is 2+2?', got %q", chatReq.Messages[0].ContentString())
	}
	if chatReq.Messages[1].Role != "assistant" {
		t.Errorf("expected second message role 'assistant', got %q", chatReq.Messages[1].Role)
	}
	if chatReq.Messages[2].ContentString() != "And 3+3?" {
		t.Errorf("expected third message 'And 3+3?', got %q", chatReq.Messages[2].ContentString())
	}
}

func TestResponsesBridge_WithInstructions(t *testing.T) {
	mc := newResponseMockCacher()
	cache := NewResponseContextCache(mc)
	bridge := NewResponsesBridge(cache, nil)

	input, _ := json.Marshal("Hello")
	req := &CreateResponseRequest{
		Model:        "gpt-4o",
		Input:        input,
		Instructions: "You are a pirate.",
	}

	chatReq, err := bridge.ToChatCompletion(context.Background(), req)
	if err != nil {
		t.Fatalf("ToChatCompletion failed: %v", err)
	}

	if len(chatReq.Messages) != 2 {
		t.Fatalf("expected 2 messages (system + user), got %d", len(chatReq.Messages))
	}
	if chatReq.Messages[0].Role != "system" {
		t.Errorf("expected first message role 'system', got %q", chatReq.Messages[0].Role)
	}
	if !strings.Contains(chatReq.Messages[0].ContentString(), "pirate") {
		t.Errorf("expected system message to contain 'pirate'")
	}
}

func TestResponsesBridge_StoreConversationContext(t *testing.T) {
	mc := newResponseMockCacher()
	cache := NewResponseContextCache(mc)
	bridge := NewResponsesBridge(cache, nil)
	ctx := context.Background()

	inputMsgs := []Message{
		mustTextMessage("user", "Hello"),
	}
	bridge.StoreConversationContext(ctx, "resp_new", inputMsgs, "Hi there!")

	// Verify the context was stored
	loaded, err := cache.LoadContext(ctx, "resp_new")
	if err != nil {
		t.Fatalf("LoadContext failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(loaded))
	}
	if loaded[0].Role != "user" {
		t.Errorf("expected role 'user', got %q", loaded[0].Role)
	}
	if loaded[1].Role != "assistant" {
		t.Errorf("expected role 'assistant', got %q", loaded[1].Role)
	}
}
