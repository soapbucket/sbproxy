package rule

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkRequestRule_Match_Legacy_Multiple(b *testing.B) {
	rules := RequestRules{
		{Methods: []string{"GET"}, Path: &PathConditions{Prefix: "/api"}},
		{Query: &QueryConditions{Exact: map[string]string{"q": "test"}}},
		{Query: &QueryConditions{Exact: map[string]string{"other": "123"}}},
		{Headers: &HeaderConditions{Exact: map[string]string{"X-Test": "value"}}},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/other/test?q=not-test&other=456", nil)
	req.Header.Set("X-Test", "not-value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Manually call non-optimized Match for each rule to simulate legacy behavior
		for _, rule := range rules {
			if rule.Match(req) {
				break
			}
		}
	}
}

func BenchmarkRequestRules_Match_Optimized_Multiple(b *testing.B) {
	rules := RequestRules{
		{Methods: []string{"GET"}, Path: &PathConditions{Prefix: "/api"}},
		{Query: &QueryConditions{Exact: map[string]string{"q": "test"}}},
		{Query: &QueryConditions{Exact: map[string]string{"other": "123"}}},
		{Headers: &HeaderConditions{Exact: map[string]string{"X-Test": "value"}}},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/other/test?q=not-test&other=456", nil)
	req.Header.Set("X-Test", "not-value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rules.Match(req)
	}
}
