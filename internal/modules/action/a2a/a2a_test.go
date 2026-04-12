package a2a_test

import (
	"encoding/json"
	"testing"

	a2amod "github.com/soapbucket/sbproxy/internal/modules/action/a2a"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"agent_card":{"name":"test-agent","url":"https://agent.example.com"}}`)
	h, err := a2amod.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := a2amod.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_MissingAgentName(t *testing.T) {
	_, err := a2amod.New(json.RawMessage(`{"agent_card":{"url":"https://agent.example.com"}}`))
	if err == nil {
		t.Fatal("expected error when agent_card.name is missing")
	}
}

func TestNew_WithTaskTimeout(t *testing.T) {
	raw := json.RawMessage(`{"agent_card":{"name":"test","url":"https://agent.example.com"},"task_timeout":"30s"}`)
	h, err := a2amod.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestNew_InvalidTaskTimeout(t *testing.T) {
	raw := json.RawMessage(`{"agent_card":{"name":"test","url":"https://agent.example.com"},"task_timeout":"not-a-duration"}`)
	_, err := a2amod.New(raw)
	if err == nil {
		t.Fatal("expected error for invalid task_timeout")
	}
}

func TestType(t *testing.T) {
	h, _ := a2amod.New(json.RawMessage(`{"agent_card":{"name":"test","url":"https://agent.example.com"}}`))
	if h.Type() != "a2a" {
		t.Errorf("Type() = %q, want %q", h.Type(), "a2a")
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("a2a")
	if !ok {
		t.Error("a2a action not registered in plugin registry")
	}
}
