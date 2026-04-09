package ai

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParamFilter_FilterParams(t *testing.T) {
	temp := 0.7
	n := 3
	pp := 0.5
	fp := 0.3
	seed := int64(42)

	makeReq := func() *ChatCompletionRequest {
		return &ChatCompletionRequest{
			Model:            "gpt-4",
			Temperature:      &temp,
			N:                &n,
			PresencePenalty:  &pp,
			FrequencyPenalty: &fp,
			LogitBias:        map[string]int{"123": 5},
			Seed:             &seed,
		}
	}

	tests := []struct {
		name         string
		providerType string
		checkNil     []string
		checkKept    []string
	}{
		{
			name:         "openai keeps all params",
			providerType: "openai",
			checkKept:    []string{"n", "logit_bias", "presence_penalty", "frequency_penalty", "seed"},
		},
		{
			name:         "anthropic strips logit_bias, n, presence_penalty, frequency_penalty",
			providerType: "anthropic",
			checkNil:     []string{"n", "logit_bias", "presence_penalty", "frequency_penalty"},
			checkKept:    []string{"seed"},
		},
		{
			name:         "bedrock strips logit_bias and n",
			providerType: "bedrock",
			checkNil:     []string{"n", "logit_bias"},
			checkKept:    []string{"presence_penalty", "frequency_penalty", "seed"},
		},
		{
			name:         "gemini strips logit_bias and n",
			providerType: "gemini",
			checkNil:     []string{"n", "logit_bias"},
			checkKept:    []string{"presence_penalty", "frequency_penalty", "seed"},
		},
		{
			name:         "ollama strips logit_bias and seed",
			providerType: "ollama",
			checkNil:     []string{"logit_bias", "seed"},
			checkKept:    []string{"n", "presence_penalty", "frequency_penalty"},
		},
		{
			name:         "unknown provider passes everything through",
			providerType: "unknown_provider",
			checkKept:    []string{"n", "logit_bias", "presence_penalty", "frequency_penalty", "seed"},
		},
		{
			name:         "empty provider passes everything through",
			providerType: "",
			checkKept:    []string{"n", "logit_bias", "presence_penalty", "frequency_penalty", "seed"},
		},
	}

	f := NewParamFilter()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeReq()
			f.FilterParams(tt.providerType, req)

			for _, param := range tt.checkNil {
				switch param {
				case "n":
					assert.Nil(t, req.N, "expected N to be nil")
				case "logit_bias":
					assert.Nil(t, req.LogitBias, "expected LogitBias to be nil")
				case "presence_penalty":
					assert.Nil(t, req.PresencePenalty, "expected PresencePenalty to be nil")
				case "frequency_penalty":
					assert.Nil(t, req.FrequencyPenalty, "expected FrequencyPenalty to be nil")
				case "seed":
					assert.Nil(t, req.Seed, "expected Seed to be nil")
				}
			}

			for _, param := range tt.checkKept {
				switch param {
				case "n":
					assert.NotNil(t, req.N, "expected N to be kept")
				case "logit_bias":
					assert.NotNil(t, req.LogitBias, "expected LogitBias to be kept")
				case "presence_penalty":
					assert.NotNil(t, req.PresencePenalty, "expected PresencePenalty to be kept")
				case "frequency_penalty":
					assert.NotNil(t, req.FrequencyPenalty, "expected FrequencyPenalty to be kept")
				case "seed":
					assert.NotNil(t, req.Seed, "expected Seed to be kept")
				}
			}

			// Temperature should always be preserved
			assert.NotNil(t, req.Temperature)
			assert.Equal(t, 0.7, *req.Temperature)
		})
	}
}

func TestParamFilter_FilterParams_NilRequest(t *testing.T) {
	f := NewParamFilter()
	f.FilterParams("anthropic", nil)
}

func TestParamFilter_FilterParams_ZeroValueFields(t *testing.T) {
	f := NewParamFilter()
	req := &ChatCompletionRequest{Model: "claude-3"}
	f.FilterParams("anthropic", req)
	assert.Nil(t, req.N)
	assert.Nil(t, req.LogitBias)
	assert.Nil(t, req.PresencePenalty)
	assert.Nil(t, req.FrequencyPenalty)
}

func TestParamFilter_UnsupportedParams(t *testing.T) {
	f := NewParamFilter()

	tests := []struct {
		name         string
		providerType string
		wantLen      int
		wantContains []string
	}{
		{
			name:         "openai has no unsupported params",
			providerType: "openai",
			wantLen:      0,
		},
		{
			name:         "anthropic has 4 unsupported params",
			providerType: "anthropic",
			wantLen:      4,
			wantContains: []string{"logit_bias", "n", "presence_penalty", "frequency_penalty"},
		},
		{
			name:         "bedrock has 2 unsupported params",
			providerType: "bedrock",
			wantLen:      2,
			wantContains: []string{"logit_bias", "n"},
		},
		{
			name:         "unknown provider returns nil",
			providerType: "unknown",
			wantLen:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := f.UnsupportedParams(tt.providerType)
			assert.Len(t, result, tt.wantLen)
			if len(tt.wantContains) > 0 {
				sort.Strings(result)
				sort.Strings(tt.wantContains)
				assert.ElementsMatch(t, tt.wantContains, result)
			}
		})
	}
}
