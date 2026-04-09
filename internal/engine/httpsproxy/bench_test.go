package httpsproxy

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func BenchmarkProxyAuthHeaderParsing(b *testing.B) {
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("origin-123:key-abc"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = parseProxyAuthorization(auth)
	}
}

func BenchmarkHostnameMatcher(b *testing.B) {
	patterns := []string{
		"api.example.com",
		"*.internal.example.com",
		"*.svc.cluster.local",
		"allowed.example.net",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hostnameMatches(patterns, "foo.internal.example.com")
	}
}

func BenchmarkTargetACLMatcher(b *testing.B) {
	patterns := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		patterns = append(patterns, "*.svc-"+string(rune('a'+(i%26)))+".example.com")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hostnameMatches(patterns, "foo.svc-a.example.com")
	}
}

func BenchmarkMatchAIRequest(b *testing.B) {
	registry := config.NewAIRegistry()
	_ = registry.RegisterMultiple([]config.AIProviderConfig{
		{
			Type:      "openai",
			Hostnames: []string{"api.openai.com"},
			Ports:     []int{443},
			Endpoints: []string{"/v1/chat/completions"},
		},
	})
	target := &connectTarget{Hostname: "api.openai.com", Port: "443"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = matchAIRequest(registry, target, "/v1/chat/completions")
	}
}

func BenchmarkPopulateAIUsageFromBody(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	w := &responseTrackingWriter{
		ResponseWriter: &httptestResponseWriter{header: make(http.Header)},
		statusCode:     http.StatusOK,
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rd := &reqctx.RequestData{
			AIUsage: &reqctx.AIUsage{Provider: "openai", Model: "gpt-4o"},
		}
		populateAIUsageFromBody(rd, w)
	}
}

