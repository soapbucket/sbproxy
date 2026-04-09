package guardrails

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaGuard_ValidJSON(t *testing.T) {
	g, err := NewSchemaGuard(json.RawMessage(`{
		"schema": {"type": "object", "required": ["answer"], "properties": {"answer": {"type": "string"}}}
	}`))
	require.NoError(t, err)

	content := testContent(`{"answer": "42"}`)
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestSchemaGuard_InvalidJSON(t *testing.T) {
	g, err := NewSchemaGuard(json.RawMessage(`{
		"schema": {"type": "object", "required": ["answer"]}
	}`))
	require.NoError(t, err)

	content := testContent(`{"wrong": "field"}`)
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Reason, "does not match schema")
}

func TestSchemaGuard_NotJSON(t *testing.T) {
	g, err := NewSchemaGuard(json.RawMessage(`{
		"schema": {"type": "object"}
	}`))
	require.NoError(t, err)

	content := testContent("This is plain text, not JSON")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Contains(t, result.Reason, "not valid JSON")
}

func TestSchemaGuard_EmptyContent(t *testing.T) {
	g, err := NewSchemaGuard(json.RawMessage(`{
		"schema": {"type": "object"}
	}`))
	require.NoError(t, err)

	content := &Content{}
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass) // Empty is allowed
}

func TestSchemaGuard_ComplexSchema(t *testing.T) {
	g, err := NewSchemaGuard(json.RawMessage(`{
		"schema": {
			"type": "object",
			"required": ["name", "age"],
			"properties": {
				"name": {"type": "string", "minLength": 1},
				"age": {"type": "integer", "minimum": 0}
			}
		}
	}`))
	require.NoError(t, err)

	// Valid
	content := testContent(`{"name": "Alice", "age": 30}`)
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass)

	// Invalid age type
	content = testContent(`{"name": "Bob", "age": "thirty"}`)
	result, err = g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
}

func TestSchemaGuard_NoSchema(t *testing.T) {
	_, err := NewSchemaGuard(json.RawMessage(`{}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires a schema")
}

func TestSchemaGuard_InvalidSchema(t *testing.T) {
	_, err := NewSchemaGuard(json.RawMessage(`{"schema": "not-a-schema"}`))
	assert.Error(t, err)
}

func TestSchemaGuard_Name(t *testing.T) {
	g, err := NewSchemaGuard(json.RawMessage(`{"schema": {"type": "object"}}`))
	require.NoError(t, err)
	assert.Equal(t, "json_schema", g.Name())
	assert.Equal(t, PhaseOutput, g.Phase())
}
