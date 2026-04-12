package waf

import (
	"net/http"
	"net/url"
	"testing"
)

func TestWAFSQLInjectionDetection(t *testing.T) {
	// Create the WAF rule from the config
	rule := WAFRule{
		ID:       "block-sql-injection",
		Name:     "Block SQL Injection",
		Enabled:  true,
		Phase:    2,
		Severity: "critical",
		Action:   "block",
		Variables: []WAFVariable{
			{
				Name:            "ARGS",
				Collection:      "ARGS",
				Transformations: []string{"lowercase", "urlDecode"},
			},
		},
		Operator: "rx",
		Pattern:  "(?i)(union|select|insert|delete|update|drop|create|alter|or|and)",
	}

	// Create rule engine
	engine, err := NewRuleEngine([]WAFRule{rule})
	if err != nil {
		t.Fatalf("Failed to create rule engine: %v", err)
	}

	// Test case 1: SQL injection in query parameter
	t.Run("SQL injection in query param", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := &http.Request{
			Method: "GET",
			URL:    reqURL,
		}

		matches, err := engine.EvaluateRequest(req.Context(), req)
		if err != nil {
			t.Fatalf("Error evaluating request: %v", err)
		}

		if len(matches) == 0 {
			t.Error("Expected WAF rule to match SQL injection pattern, but no matches found")
			t.Logf("Query string: %s", reqURL.RawQuery)
			t.Logf("Query values: %v", reqURL.Query())

			// Check what variables are extracted
			values := ExtractVariables(req, rule.Variables[0])
			t.Logf("Extracted ARGS values: %v", values)

			// Check transformations
			if len(values) > 0 {
				transformed := ApplyTransformations(values[0], rule.Variables[0].Transformations)
				t.Logf("Transformed value: %s", transformed)
				t.Logf("Pattern: %s", rule.Pattern)
			}
		} else {
			t.Logf("WAF rule matched: %+v", matches[0])
		}
	})

	// Test case 2: Normal request (should not match)
	t.Run("Normal request", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=123")
		req := &http.Request{
			Method: "GET",
			URL:    reqURL,
		}

		matches, err := engine.EvaluateRequest(req.Context(), req)
		if err != nil {
			t.Fatalf("Error evaluating request: %v", err)
		}

		if len(matches) > 0 {
			t.Errorf("Expected no matches for normal request, but got %d matches", len(matches))
		}
	})

	// Test case 3: Direct "OR" in query
	t.Run("Direct OR in query", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=1 OR 1")
		req := &http.Request{
			Method: "GET",
			URL:    reqURL,
		}

		matches, err := engine.EvaluateRequest(req.Context(), req)
		if err != nil {
			t.Fatalf("Error evaluating request: %v", err)
		}

		if len(matches) == 0 {
			t.Error("Expected WAF rule to match 'OR' pattern, but no matches found")
		} else {
			t.Logf("WAF rule matched: %+v", matches[0])
		}
	})
}
