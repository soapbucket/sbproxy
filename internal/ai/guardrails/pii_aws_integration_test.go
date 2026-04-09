package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPIIRedaction_AWSKeyInChatMessage verifies that an AWS access key
// (AKIA prefix) embedded in a chat message is redacted by the PII
// redaction guardrail before it reaches the upstream provider.
func TestPIIRedaction_AWSKeyInChatMessage(t *testing.T) {
	g, err := NewPIIRedaction(json.RawMessage(`{"detect": ["api_key"]}`))
	require.NoError(t, err)

	content := testContent("Use key AKIAIOSFODNN7EXAMPLE to authenticate with the service")

	// Step 1: Check should detect PII
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass, "PII check should detect the AWS key")
	assert.Equal(t, ActionTransform, result.Action, "action should be transform for redaction")

	// Step 2: Transform should redact the key
	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)
	text := transformed.ExtractText()
	assert.NotContains(t, text, "AKIAIOSFODNN7EXAMPLE", "AWS key should be redacted from output")
	assert.Contains(t, text, "REDACTED", "redaction marker should be present")
	// Non-PII text should be preserved
	assert.Contains(t, text, "authenticate with the service")
}

// TestPIIRedaction_AWSKeyMultipleMessages verifies that AWS keys are
// redacted across all messages in a multi-turn conversation.
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

	// Both messages containing the key should be redacted
	text0 := transformed.Messages[0].ContentString()
	assert.NotContains(t, text0, "AKIAIOSFODNN7EXAMPLE")

	// Message without key should pass through unchanged
	text1 := transformed.Messages[1].ContentString()
	assert.Equal(t, "What was my key again?", text1)

	text2 := transformed.Messages[2].ContentString()
	assert.NotContains(t, text2, "AKIAIOSFODNN7EXAMPLE")
}

// TestPIIDetection_AWSKeyBlocks verifies that PII detection (non-redaction mode)
// correctly blocks a request containing an AWS key.
func TestPIIDetection_AWSKeyBlocks(t *testing.T) {
	g, err := NewPIIDetection(json.RawMessage(`{"detect": ["api_key"]}`))
	require.NoError(t, err)

	content := testContent("Config: access_key=AKIAIOSFODNN7EXAMPLE secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass, "should detect AWS key as PII")
	assert.Equal(t, ActionBlock, result.Action, "detection mode should block")
	assert.Contains(t, result.Reason, "PII detected")

	details := result.Details
	count, ok := details["count"].(int)
	assert.True(t, ok)
	assert.GreaterOrEqual(t, count, 1, "should detect at least 1 PII finding")
}

// TestPIIRedaction_MixedPIITypes verifies that a message with both AWS keys
// and email addresses gets all PII types redacted in a single transform pass.
func TestPIIRedaction_MixedPIITypes(t *testing.T) {
	// Detect both api_key and email types
	g, err := NewPIIRedaction(json.RawMessage(`{"detect": ["api_key", "email"]}`))
	require.NoError(t, err)

	content := testContent("Deploy with AKIAIOSFODNN7EXAMPLE. Send alerts to admin@company.com.")

	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)
	text := transformed.ExtractText()

	assert.NotContains(t, text, "AKIAIOSFODNN7EXAMPLE", "AWS key should be redacted")
	assert.NotContains(t, text, "admin@company.com", "email should be redacted")
	assert.Contains(t, text, "Deploy with", "surrounding text should be preserved")
}
