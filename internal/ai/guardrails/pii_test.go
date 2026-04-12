package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PII detection is a no-op in the open-source build. All tests verify that the
// guardrails instantiate correctly and report "pass" / no findings.

func TestPIIDetection_SSN(t *testing.T) {
	g, err := NewPIIDetection(json.RawMessage(`{"detect": ["ssn"]}`))
	require.NoError(t, err)

	content := testContent("My SSN is 123-45-6789")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass, "PII detection is a no-op in open-source build")
}

func TestPIIDetection_Email(t *testing.T) {
	g, err := NewPIIDetection(json.RawMessage(`{"detect": ["email"]}`))
	require.NoError(t, err)

	content := testContent("Email me at alice@example.com")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass, "PII detection is a no-op in open-source build")
}

func TestPIIDetection_CreditCard(t *testing.T) {
	g, err := NewPIIDetection(json.RawMessage(`{"detect": ["credit_card"]}`))
	require.NoError(t, err)

	content := testContent("Card: 4111 1111 1111 1111")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass, "PII detection is a no-op in open-source build")
}

func TestPIIDetection_Clean(t *testing.T) {
	g, err := NewPIIDetection(json.RawMessage(`{"detect": ["ssn", "email"]}`))
	require.NoError(t, err)

	content := testContent("Hello, how are you?")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestPIIDetection_EmptyContent(t *testing.T) {
	g, err := NewPIIDetection(nil)
	require.NoError(t, err)

	content := &Content{}
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestPIIDetection_DefaultDetectors(t *testing.T) {
	g, err := NewPIIDetection(nil)
	require.NoError(t, err)

	content := testContent("My SSN is 123-45-6789 and email is test@example.com")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass, "PII detection is a no-op in open-source build")
}

func TestPIIRedaction_Transform(t *testing.T) {
	g, err := NewPIIRedaction(json.RawMessage(`{"detect": ["email"]}`))
	require.NoError(t, err)

	content := testContent("Email me at alice@example.com please")

	// No-op: Check should pass (no PII detected)
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass, "PII detection is a no-op in open-source build")

	// Transform should return content unchanged
	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)
	text := transformed.ExtractText()
	assert.Contains(t, text, "alice@example.com", "PII redaction is a no-op in open-source build")
}

func TestPIIRedaction_CustomReplacement(t *testing.T) {
	g, err := NewPIIRedaction(json.RawMessage(`{"detect": ["email"], "replacement": "***"}`))
	require.NoError(t, err)

	content := testContent("Email: user@test.com")
	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)
	text := transformed.ExtractText()
	assert.Contains(t, text, "user@test.com", "PII redaction is a no-op in open-source build")
}

func TestPIIRedaction_MultipleMessages(t *testing.T) {
	g, err := NewPIIRedaction(json.RawMessage(`{"detect": ["email"]}`))
	require.NoError(t, err)

	msg1, _ := json.Marshal("First: a@b.com")
	msg2, _ := json.Marshal("Second: c@d.com")
	content := &Content{
		Messages: []ai.Message{
			{Role: "user", Content: msg1},
			{Role: "assistant", Content: msg2},
		},
	}

	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)

	// No-op: content passes through unchanged
	text0 := transformed.Messages[0].ContentString()
	assert.Contains(t, text0, "a@b.com", "PII redaction is a no-op in open-source build")
	text1 := transformed.Messages[1].ContentString()
	assert.Contains(t, text1, "c@d.com", "PII redaction is a no-op in open-source build")
}

func TestPIIDetection_Name(t *testing.T) {
	g, err := NewPIIDetection(nil)
	require.NoError(t, err)
	assert.Equal(t, "pii_detection", g.Name())
	assert.Equal(t, PhaseInput, g.Phase())
}

func TestPIIRedaction_Name(t *testing.T) {
	g, err := NewPIIRedaction(nil)
	require.NoError(t, err)
	assert.Equal(t, "pii_redaction", g.Name())
}

func TestBuildDetectors_Specific(t *testing.T) {
	detectors := buildDetectors([]string{"ssn", "email"})
	// No-op detectors are still returned
	assert.Len(t, detectors, 2)
}

func TestBuildDetectors_Empty(t *testing.T) {
	detectors := buildDetectors(nil)
	// DefaultDetectors returns nil in the open-source build
	assert.Nil(t, detectors)
}

func TestBuildDetectors_Unknown(t *testing.T) {
	detectors := buildDetectors([]string{"unknown_type"})
	// Falls back to DefaultDetectors which returns nil in the open-source build
	assert.Nil(t, detectors)
}
