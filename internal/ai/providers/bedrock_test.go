package providers

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
)

func TestBedrock_Name(t *testing.T) {
	p := &Bedrock{}
	assert.Equal(t, "bedrock", p.Name())
}

func TestBedrock_SupportsStreaming(t *testing.T) {
	p := &Bedrock{}
	assert.True(t, p.SupportsStreaming())
}

func TestBedrock_SupportsEmbeddings(t *testing.T) {
	p := &Bedrock{}
	assert.True(t, p.SupportsEmbeddings())
}

func TestBedrock_ChatCompletion_CoreBuild(t *testing.T) {
	p := &Bedrock{}
	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{}, &ai.ProviderConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in this build")
}

func TestBedrock_ChatCompletionStream_CoreBuild(t *testing.T) {
	p := &Bedrock{}
	_, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{}, &ai.ProviderConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in this build")
}

func TestBedrock_Embeddings_CoreBuild(t *testing.T) {
	p := &Bedrock{}
	_, err := p.Embeddings(t.Context(), &ai.EmbeddingRequest{}, &ai.ProviderConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available in this build")
}

func TestBedrock_ListModels_ReturnsNil(t *testing.T) {
	p := &Bedrock{}
	models, err := p.ListModels(t.Context(), &ai.ProviderConfig{})
	assert.NoError(t, err)
	assert.Nil(t, models)
}
