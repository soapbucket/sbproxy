package ai

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRequestHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		check   func(t *testing.T, ctrl *RequestHeaderControls)
	}{
		{
			name:    "cache TTL parsed",
			headers: map[string]string{"X-SB-Cache-TTL": "300"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.Equal(t, 300, ctrl.CacheTTL)
			},
		},
		{
			name:    "negative cache TTL",
			headers: map[string]string{"X-SB-Cache-TTL": "-1"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.Equal(t, -1, ctrl.CacheTTL)
			},
		},
		{
			name:    "invalid cache TTL ignored",
			headers: map[string]string{"X-SB-Cache-TTL": "not-a-number"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.Equal(t, 0, ctrl.CacheTTL)
			},
		},
		{
			name:    "skip cache true",
			headers: map[string]string{"X-SB-Skip-Cache": "true"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.True(t, ctrl.SkipCache)
			},
		},
		{
			name:    "skip cache 1",
			headers: map[string]string{"X-SB-Skip-Cache": "1"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.True(t, ctrl.SkipCache)
			},
		},
		{
			name:    "skip cache false",
			headers: map[string]string{"X-SB-Skip-Cache": "false"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.False(t, ctrl.SkipCache)
			},
		},
		{
			name:    "skip log",
			headers: map[string]string{"X-SB-Skip-Log": "yes"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.True(t, ctrl.SkipLog)
			},
		},
		{
			name:    "metadata JSON",
			headers: map[string]string{"X-SB-Metadata": `{"user_id":"u123","team":"backend"}`},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				require.NotNil(t, ctrl.Metadata)
				assert.Equal(t, "u123", ctrl.Metadata["user_id"])
				assert.Equal(t, "backend", ctrl.Metadata["team"])
			},
		},
		{
			name:    "invalid metadata JSON ignored",
			headers: map[string]string{"X-SB-Metadata": "not-json"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.Nil(t, ctrl.Metadata)
			},
		},
		{
			name:    "tags comma separated",
			headers: map[string]string{"X-SB-Tags": "env=prod, team=platform, feature=chat"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				require.NotNil(t, ctrl.Tags)
				assert.Equal(t, "prod", ctrl.Tags["env"])
				assert.Equal(t, "platform", ctrl.Tags["team"])
				assert.Equal(t, "chat", ctrl.Tags["feature"])
			},
		},
		{
			name:    "tags without values",
			headers: map[string]string{"X-SB-Tags": "debug,verbose"},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				require.NotNil(t, ctrl.Tags)
				assert.Equal(t, "", ctrl.Tags["debug"])
				assert.Equal(t, "", ctrl.Tags["verbose"])
			},
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.Equal(t, 0, ctrl.CacheTTL)
				assert.False(t, ctrl.SkipCache)
				assert.False(t, ctrl.SkipLog)
				assert.Nil(t, ctrl.Metadata)
				assert.Nil(t, ctrl.Tags)
			},
		},
		{
			name: "all headers combined",
			headers: map[string]string{
				"X-SB-Cache-TTL":  "600",
				"X-SB-Skip-Cache": "true",
				"X-SB-Skip-Log":   "on",
				"X-SB-Metadata":   `{"trace":"t-123"}`,
				"X-SB-Tags":       "env=staging",
			},
			check: func(t *testing.T, ctrl *RequestHeaderControls) {
				assert.Equal(t, 600, ctrl.CacheTTL)
				assert.True(t, ctrl.SkipCache)
				assert.True(t, ctrl.SkipLog)
				assert.Equal(t, "t-123", ctrl.Metadata["trace"])
				assert.Equal(t, "staging", ctrl.Tags["env"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			ctrl := ParseRequestHeaders(h)
			require.NotNil(t, ctrl)
			tt.check(t, ctrl)
		})
	}
}

func TestRequestHeaderControls_MergeTags(t *testing.T) {
	t.Run("merges into empty body tags", func(t *testing.T) {
		ctrl := &RequestHeaderControls{
			Tags: map[string]string{"env": "prod", "team": "ai"},
		}
		req := &ChatCompletionRequest{}
		ctrl.MergeTags(req)
		assert.Equal(t, "prod", req.SBTags["env"])
		assert.Equal(t, "ai", req.SBTags["team"])
	})

	t.Run("header tags override body tags", func(t *testing.T) {
		ctrl := &RequestHeaderControls{
			Tags: map[string]string{"env": "staging"},
		}
		req := &ChatCompletionRequest{
			SBTags: map[string]string{"env": "prod", "version": "2"},
		}
		ctrl.MergeTags(req)
		assert.Equal(t, "staging", req.SBTags["env"])
		assert.Equal(t, "2", req.SBTags["version"])
	})

	t.Run("no-op when no header tags", func(t *testing.T) {
		ctrl := &RequestHeaderControls{}
		req := &ChatCompletionRequest{
			SBTags: map[string]string{"env": "prod"},
		}
		ctrl.MergeTags(req)
		assert.Equal(t, "prod", req.SBTags["env"])
	})
}

func TestRequestHeaderControls_ApplyCacheControl(t *testing.T) {
	t.Run("skip cache sets no_cache", func(t *testing.T) {
		ctrl := &RequestHeaderControls{SkipCache: true}
		req := &ChatCompletionRequest{}
		ctrl.ApplyCacheControl(req)
		require.NotNil(t, req.SBCacheControl)
		assert.True(t, req.SBCacheControl.NoCache)
	})

	t.Run("cache TTL sets ttl_seconds", func(t *testing.T) {
		ctrl := &RequestHeaderControls{CacheTTL: 120}
		req := &ChatCompletionRequest{}
		ctrl.ApplyCacheControl(req)
		require.NotNil(t, req.SBCacheControl)
		require.NotNil(t, req.SBCacheControl.TTLSeconds)
		assert.Equal(t, 120, *req.SBCacheControl.TTLSeconds)
	})

	t.Run("no-op when no cache overrides", func(t *testing.T) {
		ctrl := &RequestHeaderControls{}
		req := &ChatCompletionRequest{}
		ctrl.ApplyCacheControl(req)
		assert.Nil(t, req.SBCacheControl)
	})

	t.Run("overrides existing cache control", func(t *testing.T) {
		ttl := 60
		ctrl := &RequestHeaderControls{CacheTTL: 300}
		req := &ChatCompletionRequest{
			SBCacheControl: &CacheControl{TTLSeconds: &ttl},
		}
		ctrl.ApplyCacheControl(req)
		assert.Equal(t, 300, *req.SBCacheControl.TTLSeconds)
	})
}

func TestStripSBHeaders(t *testing.T) {
	t.Run("strips all X-SB-* headers", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-SB-Cache-TTL", "300")
		h.Set("X-SB-Skip-Cache", "true")
		h.Set("X-SB-Tags", "env=prod")
		h.Set("X-SB-Metadata", `{"foo":"bar"}`)
		h.Set("X-SB-Agent", "my-agent")
		h.Set("Content-Type", "application/json")
		h.Set("Authorization", "Bearer sk-xxx")

		StripSBHeaders(h)

		assert.Empty(t, h.Get("X-SB-Cache-TTL"))
		assert.Empty(t, h.Get("X-SB-Skip-Cache"))
		assert.Empty(t, h.Get("X-SB-Tags"))
		assert.Empty(t, h.Get("X-SB-Metadata"))
		assert.Empty(t, h.Get("X-SB-Agent"))
		assert.Equal(t, "application/json", h.Get("Content-Type"))
		assert.Equal(t, "Bearer sk-xxx", h.Get("Authorization"))
	})

	t.Run("no-op when no SB headers", func(t *testing.T) {
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		StripSBHeaders(h)
		assert.Equal(t, "application/json", h.Get("Content-Type"))
	})

	t.Run("handles empty headers", func(t *testing.T) {
		h := http.Header{}
		StripSBHeaders(h)
		assert.Empty(t, h)
	})
}

func TestParseTagsHeader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "key=value pairs",
			input: "env=prod,team=ai",
			want:  map[string]string{"env": "prod", "team": "ai"},
		},
		{
			name:  "with spaces",
			input: " env = prod , team = ai ",
			want:  map[string]string{"env": "prod", "team": "ai"},
		},
		{
			name:  "keys without values",
			input: "debug,verbose",
			want:  map[string]string{"debug": "", "verbose": ""},
		},
		{
			name:  "mixed",
			input: "env=prod,debug",
			want:  map[string]string{"env": "prod", "debug": ""},
		},
		{
			name:  "empty string",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "trailing comma",
			input: "env=prod,",
			want:  map[string]string{"env": "prod"},
		},
		{
			name:  "empty key skipped",
			input: "=value,env=prod",
			want:  map[string]string{"env": "prod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseTagsHeader(tt.input)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestParseBool(t *testing.T) {
	trueCases := []string{"1", "true", "True", "TRUE", "yes", "YES", "on", "ON", " true ", " 1 "}
	for _, v := range trueCases {
		assert.True(t, parseBool(v), "expected true for %q", v)
	}

	falseCases := []string{"0", "false", "False", "no", "off", "", "random"}
	for _, v := range falseCases {
		assert.False(t, parseBool(v), "expected false for %q", v)
	}
}
