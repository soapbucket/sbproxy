package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testContent(text string) *Content {
	raw, _ := json.Marshal(text)
	return &Content{
		Messages: []ai.Message{{Role: "user", Content: raw}},
	}
}

func TestEngine_RunInput_Block(t *testing.T) {
	cfg := &GuardrailsConfig{
		Input: []GuardrailEntry{
			{
				Type:   "max_tokens",
				Action: "block",
				Config: json.RawMessage(`{"max_tokens": 10}`),
			},
		},
	}

	engine, err := NewEngine(cfg)
	require.NoError(t, err)

	content := testContent("This is a very long text that exceeds the token limit for sure")
	_, result, _, err := engine.RunInput(context.Background(), content)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Pass)
	assert.Equal(t, ActionBlock, result.Action)
}

func TestEngine_RunInput_Pass(t *testing.T) {
	cfg := &GuardrailsConfig{
		Input: []GuardrailEntry{
			{
				Type:   "max_tokens",
				Action: "block",
				Config: json.RawMessage(`{"max_tokens": 10000}`),
			},
		},
	}

	engine, err := NewEngine(cfg)
	require.NoError(t, err)

	content := testContent("Hello")
	_, result, _, err := engine.RunInput(context.Background(), content)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestEngine_RunInput_Transform(t *testing.T) {
	cfg := &GuardrailsConfig{
		Input: []GuardrailEntry{
			{
				Type:   "pii_redaction",
				Action: "transform",
				Config: json.RawMessage(`{"detect": ["email"]}`),
			},
		},
	}

	engine, err := NewEngine(cfg)
	require.NoError(t, err)

	content := testContent("My email is test@example.com")
	transformed, result, _, err := engine.RunInput(context.Background(), content)
	require.NoError(t, err)
	assert.Nil(t, result) // Transform doesn't block

	// Content should be modified
	text := transformed.ExtractText()
	assert.NotContains(t, text, "test@example.com")
	assert.Contains(t, text, "REDACTED")
}

func TestEngine_RunInput_MultipleGuardrails(t *testing.T) {
	cfg := &GuardrailsConfig{
		Input: []GuardrailEntry{
			{
				Type:   "max_tokens",
				Action: "block",
				Config: json.RawMessage(`{"max_tokens": 10000}`),
			},
			{
				Type:   "regex_guard",
				Action: "block",
				Config: json.RawMessage(`{"deny": ["forbidden_word"]}`),
			},
		},
	}

	engine, err := NewEngine(cfg)
	require.NoError(t, err)

	// Pass both
	content := testContent("Hello world")
	_, result, _, err := engine.RunInput(context.Background(), content)
	require.NoError(t, err)
	assert.Nil(t, result)

	// Fail second
	content = testContent("This contains forbidden_word")
	_, result, _, err = engine.RunInput(context.Background(), content)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "regex_guard", result.Guardrail)
}

func TestEngine_RunInput_BlockShortCircuits(t *testing.T) {
	cfg := &GuardrailsConfig{
		Input: []GuardrailEntry{
			{
				Type:   "max_tokens",
				Action: "block",
				Config: json.RawMessage(`{"max_tokens": 1}`),
			},
			{
				Type:   "regex_guard",
				Action: "block",
				Config: json.RawMessage(`{"deny": ["test"]}`),
			},
		},
	}

	engine, err := NewEngine(cfg)
	require.NoError(t, err)

	content := testContent("This contains test text that is long")
	_, result, _, err := engine.RunInput(context.Background(), content)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Should be blocked by first guardrail (max_tokens), not regex_guard
	assert.Equal(t, "max_tokens", result.Guardrail)
}

func TestEngine_RunOutput(t *testing.T) {
	cfg := &GuardrailsConfig{
		Output: []GuardrailEntry{
			{
				Type:   "json_schema",
				Action: "flag",
				Config: json.RawMessage(`{"schema": {"type": "object", "required": ["answer"]}}`),
			},
		},
	}

	engine, err := NewEngine(cfg)
	require.NoError(t, err)
	assert.True(t, engine.HasOutput())

	// Valid JSON matching schema
	content := testContent(`{"answer": "42"}`)
	_, result, _, err := engine.RunOutput(context.Background(), content)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestEngine_Nil(t *testing.T) {
	engine, err := NewEngine(nil)
	require.NoError(t, err)
	assert.False(t, engine.HasInput())
	assert.False(t, engine.HasOutput())
}

func TestEngine_UnknownGuardrail(t *testing.T) {
	cfg := &GuardrailsConfig{
		Input: []GuardrailEntry{
			{Type: "nonexistent_guardrail"},
		},
	}

	_, err := NewEngine(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown guardrail type")
}

func TestEngine_DefaultAction(t *testing.T) {
	cfg := &GuardrailsConfig{
		Input: []GuardrailEntry{
			{
				Type:   "max_tokens",
				Config: json.RawMessage(`{"max_tokens": 1}`),
				// No Action specified — should default to "block"
			},
		},
	}

	engine, err := NewEngine(cfg)
	require.NoError(t, err)

	content := testContent("This text is too long for limit of 1")
	_, result, _, err := engine.RunInput(context.Background(), content)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, ActionBlock, result.Action)
}

func TestEngine_CheckContent_Standalone(t *testing.T) {
	engine := &Engine{}
	content := testContent("My SSN is 123-45-6789")

	results, err := engine.CheckContent(context.Background(), content, []string{"pii_detection"}, PhaseInput)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Pass)
	assert.Equal(t, "pii_detection", results[0].Guardrail)
}

func TestEngine_CheckContent_RespectsPhase(t *testing.T) {
	engine := &Engine{}
	content := testContent("you are stupid")

	results, err := engine.CheckContent(context.Background(), content, []string{"toxicity"}, PhaseInput)
	require.NoError(t, err)
	assert.Len(t, results, 0)
}
