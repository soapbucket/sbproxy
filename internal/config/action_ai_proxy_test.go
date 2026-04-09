package config

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAIProxy(t *testing.T) {
	configJSON := `{
		"type": "ai_proxy",
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test-key",
				"models": ["gpt-4", "gpt-3.5-turbo"]
			}
		],
		"default_model": "gpt-4",
		"timeout": "30s"
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy, ok := action.(*AIProxyAction)
	require.True(t, ok)

	assert.Equal(t, "gpt-4", aiProxy.DefaultModel)
	assert.Len(t, aiProxy.Providers, 1)
	assert.Equal(t, "openai", aiProxy.Providers[0].Name)
	assert.Equal(t, "openai", aiProxy.Providers[0].Type)
	assert.Equal(t, "sk-test-key", aiProxy.Providers[0].APIKey)
	assert.Equal(t, []string{"gpt-4", "gpt-3.5-turbo"}, aiProxy.Providers[0].Models)
}

func TestLoadAIProxy_NoProviders(t *testing.T) {
	configJSON := `{"type": "ai_proxy", "providers": []}`
	_, err := LoadAIProxy([]byte(configJSON))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one provider")
}

func TestLoadAIProxy_InvalidJSON(t *testing.T) {
	_, err := LoadAIProxy([]byte("not json"))
	require.Error(t, err)
}

func TestLoadAIProxy_MultipleProviders(t *testing.T) {
	configJSON := `{
		"type": "ai_proxy",
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test",
				"models": ["gpt-4"]
			},
			{
				"name": "anthropic",
				"type": "anthropic",
				"api_key": "ant-test",
				"models": ["claude-3-5-sonnet-20241022"]
			},
			{
				"name": "my-azure",
				"type": "azure",
				"api_key": "azure-key",
				"base_url": "https://myendpoint.openai.azure.com",
				"api_version": "2024-02-01",
				"deployment_map": {"gpt-4": "gpt4-deployment"}
			}
		],
		"default_model": "gpt-4"
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy := action.(*AIProxyAction)
	assert.Len(t, aiProxy.Providers, 3)
	assert.Equal(t, "azure", aiProxy.Providers[2].Type)
	assert.Equal(t, "gpt4-deployment", aiProxy.Providers[2].DeploymentMap["gpt-4"])
}

func TestAIProxyAction_GetType(t *testing.T) {
	action := &AIProxyAction{}
	assert.Equal(t, TypeAIProxy, action.GetType())
	assert.Equal(t, "ai_proxy", action.GetType())
}

func TestAIProxyAction_IsProxy(t *testing.T) {
	action := &AIProxyAction{}
	assert.False(t, action.IsProxy())
}

func TestAIProxyAction_NilReturns(t *testing.T) {
	action := &AIProxyAction{}
	assert.Nil(t, action.Rewrite())
	assert.Nil(t, action.Transport())
	assert.Nil(t, action.ModifyResponse())
	assert.Nil(t, action.ErrorHandler())
}

func TestAIProxyAction_Init(t *testing.T) {
	configJSON := `{
		"type": "ai_proxy",
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test",
				"models": ["gpt-4"]
			}
		],
		"default_model": "gpt-4"
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy := action.(*AIProxyAction)
	err = aiProxy.Init(&Config{})
	require.NoError(t, err)

	handler := aiProxy.Handler()
	assert.NotNil(t, handler)
	assert.Implements(t, (*http.Handler)(nil), handler)
}

func TestAIProxyAction_JSONRoundtrip(t *testing.T) {
	config := AIProxyActionConfig{
		DefaultModel: "gpt-4",
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)

	var decoded AIProxyActionConfig
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "gpt-4", decoded.DefaultModel)
}

func TestTypeAIProxy_Constant(t *testing.T) {
	assert.Equal(t, "ai_proxy", TypeAIProxy)
}

func TestLoaderFns_HasAIProxy(t *testing.T) {
	fn, ok := loaderFns[TypeAIProxy]
	assert.True(t, ok)
	assert.NotNil(t, fn)
}

func TestLoadAIProxy_WithRAGProvider(t *testing.T) {
	configJSON := `{
		"type": "ai_proxy",
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test",
				"models": ["gpt-4"]
			}
		],
		"default_model": "gpt-4",
		"rag_provider": {
			"type": "pinecone",
			"enabled": true,
			"config": {
				"api_key": "pc-test-key",
				"assistant_name": "my-assistant"
			}
		}
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy := action.(*AIProxyAction)
	require.NotNil(t, aiProxy.RAGProvider)
	assert.Equal(t, "pinecone", aiProxy.RAGProvider.Type)
	assert.True(t, aiProxy.RAGProvider.Enabled)
	assert.Equal(t, "pc-test-key", aiProxy.RAGProvider.Config["api_key"])
	assert.Equal(t, "my-assistant", aiProxy.RAGProvider.Config["assistant_name"])
}

func TestLoadAIProxy_WithRAGConfig(t *testing.T) {
	configJSON := `{
		"type": "ai_proxy",
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test",
				"models": ["gpt-4"]
			}
		],
		"rag": {
			"enabled": true,
			"store_type": "redis",
			"top_k": 3,
			"threshold": 0.8,
			"injection_mode": "system",
			"chunk_template": "Context:\n{{content}}"
		},
		"rag_provider": {
			"type": "redis",
			"enabled": true,
			"config": {
				"embedding_api_key": "sk-embed",
				"llm_api_key": "sk-llm",
				"redis_url": "redis://localhost:6379/0"
			}
		}
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy := action.(*AIProxyAction)

	// Verify RAG config.
	require.NotNil(t, aiProxy.RAG)
	assert.True(t, aiProxy.RAG.Enabled)
	assert.Equal(t, "redis", aiProxy.RAG.StoreType)
	assert.Equal(t, 3, aiProxy.RAG.TopK)
	assert.Equal(t, 0.8, aiProxy.RAG.Threshold)
	assert.Equal(t, "system", aiProxy.RAG.InjectionMode)

	// Verify RAG provider.
	require.NotNil(t, aiProxy.RAGProvider)
	assert.Equal(t, "redis", aiProxy.RAGProvider.Type)
	assert.True(t, aiProxy.RAGProvider.Enabled)
	assert.Equal(t, "sk-embed", aiProxy.RAGProvider.Config["embedding_api_key"])
	assert.Equal(t, "sk-llm", aiProxy.RAGProvider.Config["llm_api_key"])
	assert.Equal(t, "redis://localhost:6379/0", aiProxy.RAGProvider.Config["redis_url"])
}

func TestLoadAIProxy_WithoutRAG(t *testing.T) {
	configJSON := `{
		"type": "ai_proxy",
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test",
				"models": ["gpt-4"]
			}
		]
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy := action.(*AIProxyAction)
	assert.Nil(t, aiProxy.RAG)
	assert.Nil(t, aiProxy.RAGProvider)
}

func TestLoadAIProxy_RAGProviderSecretTag(t *testing.T) {
	// Verify that ProviderConfig.Config has secret:"true" struct tag
	// by checking the config map values are preserved (they will be resolved
	// by ProcessSecretFields during actual config loading).
	configJSON := `{
		"type": "ai_proxy",
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test",
				"models": ["gpt-4"]
			}
		],
		"rag_provider": {
			"type": "vectara",
			"enabled": true,
			"config": {
				"api_key": "{{secrets.vectara_key}}",
				"corpus_key": "my-corpus"
			}
		}
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy := action.(*AIProxyAction)
	require.NotNil(t, aiProxy.RAGProvider)
	// The template reference should be preserved as-is during parsing.
	// It gets resolved by ProcessSecretFields at config init time.
	assert.Equal(t, "{{secrets.vectara_key}}", aiProxy.RAGProvider.Config["api_key"])
	assert.Equal(t, "my-corpus", aiProxy.RAGProvider.Config["corpus_key"])
}

func TestLoadAIProxy_AllRAGProviderTypes(t *testing.T) {
	providerTypes := []string{
		"pinecone", "vectara", "bedrock", "vertex",
		"ragie", "cloudflare", "nuclia", "cohere", "redis",
	}

	for _, pt := range providerTypes {
		t.Run(pt, func(t *testing.T) {
			configJSON := `{
				"type": "ai_proxy",
				"providers": [{"name": "openai", "type": "openai", "api_key": "sk-test", "models": ["gpt-4"]}],
				"rag_provider": {
					"type": "` + pt + `",
					"enabled": true,
					"config": {"test_key": "test_value"}
				}
			}`

			action, err := LoadAIProxy([]byte(configJSON))
			require.NoError(t, err)

			aiProxy := action.(*AIProxyAction)
			require.NotNil(t, aiProxy.RAGProvider)
			assert.Equal(t, pt, aiProxy.RAGProvider.Type)
			assert.True(t, aiProxy.RAGProvider.Enabled)
			assert.Equal(t, "test_value", aiProxy.RAGProvider.Config["test_key"])
		})
	}
}

func TestLoadAIProxy_SkipTLSVerifyHost_True(t *testing.T) {
	configJSON := `{
		"type": "ai_proxy",
		"skip_tls_verify_host": true,
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test",
				"models": ["gpt-4"]
			}
		]
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy := action.(*AIProxyAction)
	assert.True(t, aiProxy.SkipTLSVerifyHost, "SkipTLSVerifyHost should be true when set in config")
}

func TestLoadAIProxy_SkipTLSVerifyHost_DefaultFalse(t *testing.T) {
	configJSON := `{
		"type": "ai_proxy",
		"providers": [
			{
				"name": "openai",
				"type": "openai",
				"api_key": "sk-test",
				"models": ["gpt-4"]
			}
		]
	}`

	action, err := LoadAIProxy([]byte(configJSON))
	require.NoError(t, err)

	aiProxy := action.(*AIProxyAction)
	assert.False(t, aiProxy.SkipTLSVerifyHost, "SkipTLSVerifyHost should default to false when not set")
}
