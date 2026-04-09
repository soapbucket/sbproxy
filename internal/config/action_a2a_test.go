package config

import (
	"encoding/json"
	"testing"
)

func TestLoadA2A(t *testing.T) {
	data := []byte(`{
		"agent_card": {
			"name": "test-agent",
			"description": "A test agent",
			"url": "http://localhost:8080",
			"version": "1.0.0",
			"capabilities": {
				"streaming": true
			},
			"skills": [
				{
					"id": "echo",
					"name": "Echo",
					"description": "Echoes back input"
				}
			]
		},
		"task_timeout": "60s"
	}`)

	action, err := LoadA2A(data)
	if err != nil {
		t.Fatalf("LoadA2A: %v", err)
	}

	a2a, ok := action.(*A2AAction)
	if !ok {
		t.Fatal("expected *A2AAction")
	}

	if a2a.AgentCard.Name != "test-agent" {
		t.Errorf("expected name 'test-agent', got %q", a2a.AgentCard.Name)
	}
	if !a2a.AgentCard.Capabilities.Streaming {
		t.Error("expected streaming capability")
	}
	if len(a2a.AgentCard.Skills) != 1 {
		t.Errorf("expected 1 skill, got %d", len(a2a.AgentCard.Skills))
	}
}

func TestLoadA2A_MissingName(t *testing.T) {
	data := []byte(`{"agent_card": {}}`)

	_, err := LoadA2A(data)
	if err == nil {
		t.Fatal("expected error for missing agent name")
	}
}

func TestLoadA2A_InvalidJSON(t *testing.T) {
	_, err := LoadA2A([]byte("invalid"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestA2AAction_GetType(t *testing.T) {
	data := []byte(`{"agent_card": {"name": "test"}}`)
	action, err := LoadA2A(data)
	if err != nil {
		t.Fatal(err)
	}
	if action.GetType() != TypeA2A {
		t.Errorf("expected %q, got %q", TypeA2A, action.GetType())
	}
}

func TestA2AAction_IsProxy(t *testing.T) {
	data := []byte(`{"agent_card": {"name": "test"}}`)
	action, err := LoadA2A(data)
	if err != nil {
		t.Fatal(err)
	}
	if action.IsProxy() {
		t.Error("expected IsProxy() to return false")
	}
}

func TestA2AAction_JSONRoundTrip(t *testing.T) {
	config := A2AActionConfig{}
	config.AgentCard.Name = "roundtrip-agent"
	config.AgentCard.URL = "http://example.com"
	config.AgentCard.Capabilities.Streaming = true

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	action, err := LoadA2A(data)
	if err != nil {
		t.Fatal(err)
	}

	a2a := action.(*A2AAction)
	if a2a.AgentCard.Name != "roundtrip-agent" {
		t.Errorf("expected 'roundtrip-agent', got %q", a2a.AgentCard.Name)
	}
}
