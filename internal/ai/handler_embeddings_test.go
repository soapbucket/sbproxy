package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeEmbeddingsInput_String(t *testing.T) {
	result, err := NormalizeEmbeddingsInput("hello world")
	require.NoError(t, err)
	assert.Equal(t, []string{"hello world"}, result)
}

func TestNormalizeEmbeddingsInput_StringSlice(t *testing.T) {
	result, err := NormalizeEmbeddingsInput([]string{"hello", "world"})
	require.NoError(t, err)
	assert.Equal(t, []string{"hello", "world"}, result)
}

func TestNormalizeEmbeddingsInput_AnySlice(t *testing.T) {
	result, err := NormalizeEmbeddingsInput([]any{"hello", "world"})
	require.NoError(t, err)
	assert.Equal(t, []string{"hello", "world"}, result)
}

func TestNormalizeEmbeddingsInput_AnySlice_NonString(t *testing.T) {
	_, err := NormalizeEmbeddingsInput([]any{"hello", 42})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "input[1] is not a string")
}

func TestNormalizeEmbeddingsInput_Nil(t *testing.T) {
	_, err := NormalizeEmbeddingsInput(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "input is required")
}

func TestNormalizeEmbeddingsInput_EmptyString(t *testing.T) {
	_, err := NormalizeEmbeddingsInput("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestNormalizeEmbeddingsInput_EmptySlice(t *testing.T) {
	_, err := NormalizeEmbeddingsInput([]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestNormalizeEmbeddingsInput_UnsupportedType(t *testing.T) {
	_, err := NormalizeEmbeddingsInput(42)
	assert.Error(t, err)
}

func TestValidateEmbeddingRequest_Valid(t *testing.T) {
	req := &EmbeddingRequest{
		Model: "text-embedding-ada-002",
		Input: "test input",
	}
	assert.NoError(t, ValidateEmbeddingRequest(req))
}

func TestValidateEmbeddingRequest_MissingModel(t *testing.T) {
	req := &EmbeddingRequest{
		Input: "test input",
	}
	err := ValidateEmbeddingRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "model is required")
}

func TestValidateEmbeddingRequest_MissingInput(t *testing.T) {
	req := &EmbeddingRequest{
		Model: "text-embedding-ada-002",
	}
	err := ValidateEmbeddingRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "input is required")
}
