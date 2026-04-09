package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecrets_OpenAIKey(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent("Here is the key: sk-abc123def456ghi789jkl012mno345pqr678")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["secret_types"], "openai_key")
}

func TestSecrets_AWSAccessKey(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent("AWS key: AKIAIOSFODNN7EXAMPLE")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["secret_types"], "aws_access_key")
}

func TestSecrets_GitHubPAT(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["secret_types"], "github_pat")
}

func TestSecrets_PrivateKey(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent("-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAK...")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["secret_types"], "private_key")
}

func TestSecrets_PasswordAssignment(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent("password=mysecretpassword123")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["secret_types"], "password_assignment")
}

func TestSecrets_APIKeyAssignment(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent(`api_key="sk-some-api-key-value"`)
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["secret_types"], "api_key_assignment")
}

func TestSecrets_SlackToken(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent("Slack token: xoxb-123456789012-abcdefghijklmn")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["secret_types"], "slack_token")
}

func TestSecrets_CleanContent(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent("Here is a summary of your request. No secrets here.")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestSecrets_MaskAction(t *testing.T) {
	g, err := NewSecretsGuardrail(json.RawMessage(`{"action": "mask"}`))
	require.NoError(t, err)

	content := testContent("Key: sk-abc123def456ghi789jkl012mno345pqr678")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Equal(t, ActionTransform, result.Action)
}

func TestSecrets_BlockAction(t *testing.T) {
	g, err := NewSecretsGuardrail(json.RawMessage(`{"action": "block"}`))
	require.NoError(t, err)

	content := testContent("Key: sk-abc123def456ghi789jkl012mno345pqr678")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Equal(t, ActionBlock, result.Action)
}

func TestSecrets_Transform(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	content := testContent("Key: sk-abc123def456ghi789jkl012mno345pqr678 and password=secret123")
	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)

	text := transformed.ExtractText()
	assert.NotContains(t, text, "sk-abc123")
	assert.NotContains(t, text, "password=secret123")
	assert.Contains(t, text, "[REDACTED]")
}

func TestSecrets_CustomMaskReplacement(t *testing.T) {
	g, err := NewSecretsGuardrail(json.RawMessage(`{"mask_replacement": "***MASKED***"}`))
	require.NoError(t, err)

	content := testContent("Key: sk-abc123def456ghi789jkl012mno345pqr678")
	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)

	text := transformed.ExtractText()
	assert.Contains(t, text, "***MASKED***")
}

func TestSecrets_CustomPatterns(t *testing.T) {
	g, err := NewSecretsGuardrail(json.RawMessage(`{
		"custom_patterns": ["my-secret-[a-z0-9]{10}"]
	}`))
	require.NoError(t, err)

	content := testContent("Token: my-secret-abcdef1234")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Details["secret_types"], "custom")
}

func TestSecrets_InvalidCustomPattern(t *testing.T) {
	_, err := NewSecretsGuardrail(json.RawMessage(`{"custom_patterns": ["[invalid"]}`))
	assert.Error(t, err)
}

func TestSecrets_EmptyContent(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)

	result, err := g.Check(context.Background(), &Content{})
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestSecrets_NameAndPhase(t *testing.T) {
	g, err := NewSecretsGuardrail(nil)
	require.NoError(t, err)
	assert.Equal(t, "secrets", g.Name())
	assert.Equal(t, PhaseOutput, g.Phase())
}
