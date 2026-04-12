package modifier

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/soapbucket/sbproxy/internal/middleware/rule"
)

func TestRequestModifier_Match(t *testing.T) {
	tests := []struct {
		name     string
		modifier RequestModifier
		req      *http.Request
		expected bool
	}{
		{
			name:     "Nil rule matches everything",
			modifier: RequestModifier{Rules: nil, URL: &URLModifications{Set: "https://example.com"}},
			req:      mustCreateRequest("GET", "https://original.com/path", t),
			expected: true,
		},
		{
			name:     "Empty rule matches everything",
			modifier: RequestModifier{Rules: rule.RequestRules{rule.EmptyRequestRule}, URL: &URLModifications{Set: "https://example.com"}},
			req:      mustCreateRequest("GET", "https://original.com/path", t),
			expected: true,
		},
		{
			name: "Matching rule returns true",
			modifier: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path"}}},
				URL:   &URLModifications{Set: "https://new.example.com"},
			},
			req:      mustCreateRequest("GET", "https://example.com/path", t),
			expected: true,
		},
		{
			name: "Non-matching rule returns false",
			modifier: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path"}}},
				URL:   &URLModifications{Set: "https://new.example.com"},
			},
			req:      mustCreateRequest("GET", "https://example.com/other", t),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.modifier.Match(tt.req)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRequestModifier_Apply(t *testing.T) {
	tests := []struct {
		name          string
		modifier      RequestModifier
		req           *http.Request
		expectedURL   string
		shouldModify  bool
		expectedError bool
	}{
		{
			name: "Apply with nil rule modifies request",
			modifier: RequestModifier{
				Rules: nil,
				URL:   &URLModifications{Set: "https://new.example.com/path"},
			},
			req:           mustCreateRequest("GET", "https://original.com/old", t),
			expectedURL:   "https://new.example.com/path",
			shouldModify:  true,
			expectedError: false,
		},
		{
			name: "Apply with matching rule modifies request",
			modifier: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://original.com/match"}}},
				URL:   &URLModifications{Set: "https://new.example.com/target"},
			},
			req:           mustCreateRequest("GET", "https://original.com/match", t),
			expectedURL:   "https://new.example.com/target",
			shouldModify:  true,
			expectedError: false,
		},
		{
			name: "Apply with non-matching rule does not modify request",
			modifier: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://original.com/match"}}},
				URL:   &URLModifications{Set: "https://new.example.com/target"},
			},
			req:           mustCreateRequest("GET", "https://original.com/no-match", t),
			expectedURL:   "https://original.com/no-match",
			shouldModify:  false,
			expectedError: false,
		},
		{
			name: "Apply with invalid URL returns error",
			modifier: RequestModifier{
				Rules: nil,
				URL:   &URLModifications{Set: "://invalid-url"},
			},
			req:           mustCreateRequest("GET", "https://original.com/path", t),
			expectedURL:   "https://original.com/path",
			shouldModify:  false,
			expectedError: true,
		},
		{
			name: "Apply with empty rule modifies request",
			modifier: RequestModifier{
				Rules: rule.RequestRules{rule.EmptyRequestRule},
				URL:   &URLModifications{Set: "https://new.example.com/path?query=value"},
			},
			req:           mustCreateRequest("GET", "https://original.com/old", t),
			expectedURL:   "https://new.example.com/path?query=value",
			shouldModify:  true,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalURL := tt.req.URL.String()
			err := tt.modifier.Apply(tt.req)

			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			resultURL := tt.req.URL.String()
			if tt.shouldModify && resultURL != tt.expectedURL {
				t.Errorf("Expected URL to be modified to %s, got %s", tt.expectedURL, resultURL)
			}
			if !tt.shouldModify && resultURL != originalURL {
				t.Errorf("Expected URL to remain %s, got %s", originalURL, resultURL)
			}
		})
	}
}

func TestRequestModifiers_Apply(t *testing.T) {
	tests := []struct {
		name          string
		modifiers     RequestModifiers
		req           *http.Request
		expectedURL   string
		expectedError bool
	}{
		{
			name:          "Empty modifiers do not change request",
			modifiers:     RequestModifiers{},
			req:           mustCreateRequest("GET", "https://original.com/path", t),
			expectedURL:   "https://original.com/path",
			expectedError: false,
		},
		{
			name: "Single modifier applies",
			modifiers: RequestModifiers{
				{
					Rules: nil,
					URL:   &URLModifications{Set: "https://new.example.com/path"},
				},
			},
			req:           mustCreateRequest("GET", "https://original.com/old", t),
			expectedURL:   "https://new.example.com/path",
			expectedError: false,
		},
		{
			name: "Multiple modifiers apply in order",
			modifiers: RequestModifiers{
				{
					Rules: nil,
					URL:   &URLModifications{Set: "https://first.com/path"},
				},
				{
					Rules: rule.RequestRules{},
					URL:   &URLModifications{Set: "https://second.com/path"},
				},
			},
			req:           mustCreateRequest("GET", "https://original.com/old", t),
			expectedURL:   "https://second.com/path",
			expectedError: false,
		},
		{
			name: "Modifiers with rules apply only matching ones",
			modifiers: RequestModifiers{
				{
					Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://original.com/no-match"}}},
					URL:   &URLModifications{Set: "https://skip.com/path"},
				},
				{
					Rules: nil,
					URL:   &URLModifications{Set: "https://apply.com/path"},
				},
			},
			req:           mustCreateRequest("GET", "https://original.com/other", t),
			expectedURL:   "https://apply.com/path",
			expectedError: false,
		},
		{
			name: "Error in modifier stops processing",
			modifiers: RequestModifiers{
				{
					Rules: nil,
					URL:   &URLModifications{Set: "://invalid-url"},
				},
				{
					Rules: nil,
					URL:   &URLModifications{Set: "https://should-not-apply.com/path"},
				},
			},
			req:           mustCreateRequest("GET", "https://original.com/path", t),
			expectedURL:   "https://original.com/path",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.modifiers.Apply(tt.req)

			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			resultURL := tt.req.URL.String()
			if resultURL != tt.expectedURL {
				t.Errorf("Expected URL %s, got %s", tt.expectedURL, resultURL)
			}
		})
	}
}

func TestRequestModifier_JSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want RequestModifier
	}{
		{
			name: "Modifier with rule and URL",
			json: `{"rules":[{"url":{"exact":"https://example.com/path"}}],"url":{"set":"https://new.example.com/target"}}`,
			want: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path"}}},
				URL:   &URLModifications{Set: "https://new.example.com/target"},
			},
		},
		{
			name: "Modifier without rule (nil rule)",
			json: `{"url":{"set":"https://new.example.com/target"}}`,
			want: RequestModifier{
				Rules: nil,
				URL:   &URLModifications{Set: "https://new.example.com/target"},
			},
		},
		{
			name: "Modifier with empty rule",
			json: `{"rules":[{"url":{"exact":""}}],"url":{"set":"https://new.example.com/target"}}`,
			want: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: ""}}},
				URL:   &URLModifications{Set: "https://new.example.com/target"},
			},
		},
		{
			name: "Modifier with URL containing query params",
			json: `{"url":{"set":"https://new.example.com/target?key=value&other=test"}}`,
			want: RequestModifier{
				Rules: nil,
				URL:   &URLModifications{Set: "https://new.example.com/target?key=value&other=test"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshaling from JSON
			var got RequestModifier
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}
			if got.URL == nil && tt.want.URL == nil {
				// Both nil, skip
			} else if got.URL == nil || tt.want.URL == nil {
				t.Errorf("Expected URL nil=%v, got nil=%v", tt.want.URL == nil, got.URL == nil)
			} else if got.URL.Set != tt.want.URL.Set {
				t.Errorf("Expected URL.Set=%s, got %s", tt.want.URL.Set, got.URL.Set)
			}
			if len(got.Rules) != len(tt.want.Rules) {
				t.Errorf("Expected Rules length=%d, got %d", len(tt.want.Rules), len(got.Rules))
			}
			if len(got.Rules) > 0 && len(tt.want.Rules) > 0 {
				if got.Rules[0].URL == nil && tt.want.Rules[0].URL == nil {
					// Both nil, skip
				} else if got.Rules[0].URL == nil || tt.want.Rules[0].URL == nil {
					t.Errorf("Expected Rules[0].URL nil=%v, got nil=%v", tt.want.Rules[0].URL == nil, got.Rules[0].URL == nil)
				} else if got.Rules[0].URL.Exact != tt.want.Rules[0].URL.Exact {
					t.Errorf("Expected Rules[0].URL.Exact=%s, got %s", tt.want.Rules[0].URL.Exact, got.Rules[0].URL.Exact)
				}
			}

			// Test marshaling to JSON
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Failed to marshal JSON: %v", err)
			}

			// Unmarshal again to verify round-trip
			var roundTrip RequestModifier
			if err := json.Unmarshal(data, &roundTrip); err != nil {
				t.Fatalf("Failed to unmarshal round-trip JSON: %v", err)
			}
			if roundTrip.URL == nil && tt.want.URL == nil {
				// Both nil, skip
			} else if roundTrip.URL == nil || tt.want.URL == nil {
				t.Errorf("Round-trip failed: Expected URL nil=%v, got nil=%v", tt.want.URL == nil, roundTrip.URL == nil)
			} else if roundTrip.URL.Set != tt.want.URL.Set {
				t.Errorf("Round-trip failed: Expected URL.Set=%s, got %s", tt.want.URL.Set, roundTrip.URL.Set)
			}
		})
	}
}

func TestRequestModifiers_JSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want RequestModifiers
	}{
		{
			name: "Single modifier",
			json: `[{"url":{"set":"https://new.example.com/path"}}]`,
			want: RequestModifiers{
				{URL: &URLModifications{Set: "https://new.example.com/path"}},
			},
		},
		{
			name: "Multiple modifiers",
			json: `[{"rules":[{"url":{"exact":"https://example.com/path1"}}],"url":{"set":"https://new1.com"}},{"url":{"set":"https://new2.com"}}]`,
			want: RequestModifiers{
				{
					Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path1"}}},
					URL:   &URLModifications{Set: "https://new1.com"},
				},
				{
					Rules: nil,
					URL:   &URLModifications{Set: "https://new2.com"},
				},
			},
		},
		{
			name: "Empty modifiers",
			json: `[]`,
			want: RequestModifiers{},
		},
		{
			name: "Modifiers with various rule configurations",
			json: `[{"url":{"set":"https://new1.com"}},{"rules":[{"url":{"exact":""}}],"url":{"set":"https://new2.com"}}]`,
			want: RequestModifiers{
				{Rules: nil, URL: &URLModifications{Set: "https://new1.com"}},
				{Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: ""}}}, URL: &URLModifications{Set: "https://new2.com"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshaling from JSON
			var got RequestModifiers
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Expected %d modifiers, got %d", len(tt.want), len(got))
			}
			for i := range got {
				if got[i].URL == nil && tt.want[i].URL == nil {
					// Both nil, skip
				} else if got[i].URL == nil || tt.want[i].URL == nil {
					t.Errorf("Modifier %d: Expected URL nil=%v, got nil=%v", i, tt.want[i].URL == nil, got[i].URL == nil)
				} else if got[i].URL.Set != tt.want[i].URL.Set {
					t.Errorf("Modifier %d: Expected URL.Set=%s, got %s", i, tt.want[i].URL.Set, got[i].URL.Set)
				}
			}

			// Test marshaling to JSON
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Failed to marshal JSON: %v", err)
			}

			// Unmarshal again to verify round-trip
			var roundTrip RequestModifiers
			if err := json.Unmarshal(data, &roundTrip); err != nil {
				t.Fatalf("Failed to unmarshal round-trip JSON: %v", err)
			}
			if len(roundTrip) != len(tt.want) {
				t.Fatalf("Round-trip failed: Expected %d modifiers, got %d", len(tt.want), len(roundTrip))
			}
		})
	}
}

func mustCreateRequest(method, rawURL string, t *testing.T) *http.Request {
	t.Helper()
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Failed to parse URL %s: %v", rawURL, err)
	}
	req := &http.Request{
		Method: method,
		URL:    parsedURL,
		Header: make(http.Header),
	}
	return req
}

func TestRequestModifier_HeaderModifications(t *testing.T) {
	tests := []struct {
		name           string
		modifier       RequestModifier
		req            *http.Request
		expectedHeader http.Header
	}{
		{
			name: "Set header creates new header",
			modifier: RequestModifier{
				Headers: &HeaderModifications{
					Set: map[string]string{"X-Custom": "value1"},
				},
			},
			req: mustCreateRequest("GET", "https://example.com", t),
			expectedHeader: http.Header{
				"X-Custom": []string{"value1"},
			},
		},
		{
			name: "Set header overwrites existing",
			modifier: RequestModifier{
				Headers: &HeaderModifications{
					Set: map[string]string{"X-Custom": "new-value"},
				},
			},
			req: func() *http.Request {
				r := mustCreateRequest("GET", "https://example.com", t)
				r.Header.Set("X-Custom", "old-value")
				return r
			}(),
			expectedHeader: http.Header{
				"X-Custom": []string{"new-value"},
			},
		},
		{
			name: "Add header creates new header",
			modifier: RequestModifier{
				Headers: &HeaderModifications{
					Add: map[string]string{"X-Add": "value1"},
				},
			},
			req: mustCreateRequest("GET", "https://example.com", t),
			expectedHeader: http.Header{
				"X-Add": []string{"value1"},
			},
		},
		{
			name: "Add header appends to existing",
			modifier: RequestModifier{
				Headers: &HeaderModifications{
					Add: map[string]string{"X-Add": "value2"},
				},
			},
			req: func() *http.Request {
				r := mustCreateRequest("GET", "https://example.com", t)
				r.Header.Set("X-Add", "value1")
				return r
			}(),
			expectedHeader: http.Header{
				"X-Add": []string{"value1", "value2"},
			},
		},
		{
			name: "Delete header removes header",
			modifier: RequestModifier{
				Headers: &HeaderModifications{
					Delete: []string{"X-Remove"},
				},
			},
			req: func() *http.Request {
				r := mustCreateRequest("GET", "https://example.com", t)
				r.Header.Set("X-Remove", "value")
				r.Header.Set("X-Keep", "value")
				return r
			}(),
			expectedHeader: http.Header{
				"X-Keep": []string{"value"},
			},
		},
		{
			name: "Delete, Set, Add in correct order",
			modifier: RequestModifier{
				Headers: &HeaderModifications{
					Delete: []string{"X-Old"},
					Set:    map[string]string{"X-Set": "set-value"},
					Add:    map[string]string{"X-Add": "add-value"},
				},
			},
			req: func() *http.Request {
				r := mustCreateRequest("GET", "https://example.com", t)
				r.Header.Set("X-Old", "remove-me")
				r.Header.Set("X-Set", "old-value")
				return r
			}(),
			expectedHeader: http.Header{
				"X-Set": []string{"set-value"},
				"X-Add": []string{"add-value"},
			},
		},
		{
			name: "Headers modification with matching rule",
			modifier: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/match"}}},
				Headers: &HeaderModifications{
					Set: map[string]string{"X-Matched": "yes"},
				},
			},
			req: mustCreateRequest("GET", "https://example.com/match", t),
			expectedHeader: http.Header{
				"X-Matched": []string{"yes"},
			},
		},
		{
			name: "Headers modification with non-matching rule",
			modifier: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/match"}}},
				Headers: &HeaderModifications{
					Set: map[string]string{"X-Matched": "yes"},
				},
			},
			req:            mustCreateRequest("GET", "https://example.com/no-match", t),
			expectedHeader: http.Header{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.modifier.Apply(tt.req)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check all expected headers are present
			for name, values := range tt.expectedHeader {
				got := tt.req.Header[name]
				if len(got) != len(values) {
					t.Errorf("Header %s: Expected %d values, got %d", name, len(values), len(got))
					continue
				}
				for i, expectedValue := range values {
					if got[i] != expectedValue {
						t.Errorf("Header %s[%d]: Expected %s, got %s", name, i, expectedValue, got[i])
					}
				}
			}

			// Check no unexpected headers are present
			for name := range tt.req.Header {
				if _, exists := tt.expectedHeader[name]; !exists {
					t.Errorf("Unexpected header present: %s", name)
				}
			}
		})
	}
}

func TestRequestModifier_MethodModification(t *testing.T) {
	tests := []struct {
		name           string
		modifier       RequestModifier
		req            *http.Request
		expectedMethod string
	}{
		{
			name: "Modify method from GET to POST",
			modifier: RequestModifier{
				Method: "POST",
			},
			req:            mustCreateRequest("GET", "https://example.com", t),
			expectedMethod: "POST",
		},
		{
			name: "Modify method with lowercase",
			modifier: RequestModifier{
				Method: "put",
			},
			req:            mustCreateRequest("GET", "https://example.com", t),
			expectedMethod: "PUT",
		},
		{
			name: "Method modification with matching rule",
			modifier: RequestModifier{
				Rules:  rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/match"}}},
				Method: "POST",
			},
			req:            mustCreateRequest("GET", "https://example.com/match", t),
			expectedMethod: "POST",
		},
		{
			name: "Method modification with non-matching rule",
			modifier: RequestModifier{
				Rules:  rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/match"}}},
				Method: "POST",
			},
			req:            mustCreateRequest("GET", "https://example.com/no-match", t),
			expectedMethod: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.modifier.Apply(tt.req)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tt.req.Method != tt.expectedMethod {
				t.Errorf("Expected method %s, got %s", tt.expectedMethod, tt.req.Method)
			}
		})
	}
}
