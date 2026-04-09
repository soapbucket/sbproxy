package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PII detection is a no-op in the open-source build. These tests verify that
// the guardrails instantiate correctly and pass content through unchanged.

func TestPIIRedaction_AWSKeyInChatMessage(t *testing.T) {
	g, err := NewPIIRedaction(json.RawMessage(`{"detect": ["api_key"]}`))
	require.NoError(t, err)

	content := testContent("Use key AKIAIOSFODNN7EXAMPLE to authenticate with the service")

	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass, "PII detection is a no-op in open-source build")

	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)
	text := transformed.ExtractText()
	assert.Contains(t, text, "AKIAIOSFODNN7EXAMPLE", "PII redaction is a no-op in open-source build")
	assert.Contains(t, text, "authenticate with the service")
}

func TestPIIRedaction_AWSKeyMultipleMessages(t *testing.T) {
	g, err := NewPIIRedaction(json.RawMessage(`{"detect": ["api_key"]}`))
	require.NoError(t, err)

	msg1, _ := json.Marshal("Store this key: AKIAIOSFODNN7EXAMPLE")
	msg2, _ := json.Marshal("What was my key again?")
	msg3, _ := json.Marshal("Your key is AKIAIOSFODNN7EXAMPLE")

	content := &Content{
		Messages: []ai.Message{
			{Role: "user", Content: msg1},
			{Role: "user", Content: msg2},
			{Role: "assistant", Content: msg3},
		},
	}

	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)

	// No-op: content passes through unchanged
	text0 := transformed.Messages[0].ContentString()
	assert.Contains(t, text0, "AKIAIOSFODNN7EXAMPLE", "PII redaction is a no-op in open-source build")

	text1 := transformed.Messages[1].ContentString()
	assert.Equal(t, "What was my key again?", text1)

	text2 := transformed.Messages[2].ContentString()
	assert.Contains(t, text2, "AKIAIOSFODNN7EXAMPLE", "PII redaction is a no-op in open-source build")
}

func TestPIIDetection_AWSKeyBlocks(t *testing.T) {
	g, err := NewPIIDetection(json.RawMessage(`{"detect": ["api_key"]}`))
	require.NoError(t, err)

	content := testContent("Config: access_key=AKIAIOSFODNN7EXAMPLE secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass, "PII detection is a no-op in open-source build")
}

func TestPIIRedaction_MixedPIITypes(t *testing.T) {
	g, err := NewPIIRedaction(json.RawMessage(`{"detect": ["api_key", "email"]}`))
	require.NoError(t, err)

	content := testContent("Deploy with AKIAIOSFODNN7EXAMPLE. Send alerts to admin@company.com.")

	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)
	text := transformed.ExtractText()

	// No-op: content passes through unchanged
	assert.Contains(t, text, "AKIAIOSFODNN7EXAMPLE", "PII redaction is a no-op in open-source build")
	assert.Contains(t, text, "admin@company.com", "PII redaction is a no-op in open-source build")
	assert.Contains(t, text, "Deploy with")
}
