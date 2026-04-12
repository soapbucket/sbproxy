package forward

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/soapbucket/sbproxy/internal/middleware/rule"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestForwardRule_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     ForwardRule
		req      *http.Request
		expected bool
	}{
		{
			name: "Nil rules matches everything",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules:    nil,
			},
			req:      mustCreateRequest("GET", "https://any.com/path", t),
			expected: true,
		},
		{
			name: "Empty rules slice matches everything",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{},
			},
			req:      mustCreateRequest("GET", "https://any.com/path", t),
			expected: true,
		},
		{
			name: "Empty rule in slice matches everything",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{rule.EmptyRequestRule},
			},
			req:      mustCreateRequest("GET", "https://any.com/path", t),
			expected: true,
		},
		{
			name: "Rule matches exact URL",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://original.com/path"}}},
			},
			req:      mustCreateRequest("GET", "https://original.com/path", t),
			expected: true,
		},
		{
			name: "Rule does not match different URL",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://original.com/path"}}},
			},
			req:      mustCreateRequest("GET", "https://original.com/other", t),
			expected: false,
		},
		{
			name: "Rule matches by method",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{{Methods: []string{"POST"}}},
			},
			req:      mustCreateRequest("POST", "https://example.com/path", t),
			expected: true,
		},
		{
			name: "Rule matches by path contains",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{{Path: &rule.PathConditions{Contains: "/api"}}},
			},
			req:      mustCreateRequest("GET", "https://example.com/api/users", t),
			expected: true,
		},
		{
			name: "Rule matches by path prefix /api/v1",
			rule: ForwardRule{
				Hostname: "api-v1-backend.test",
				Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/api/v1"}}},
			},
			req:      mustCreateRequest("GET", "https://forward-rules-complex.test/api/v1/test", t),
			expected: true,
		},
		{
			name: "Rule matches by path prefix /api/v1 with longer path",
			rule: ForwardRule{
				Hostname: "api-v1-backend.test",
				Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/api/v1"}}},
			},
			req:      mustCreateRequest("GET", "https://forward-rules-complex.test/api/v1/users/123", t),
			expected: true,
		},
		{
			name: "Rule does not match different path prefix",
			rule: ForwardRule{
				Hostname: "api-v1-backend.test",
				Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/api/v1"}}},
			},
			req:      mustCreateRequest("GET", "https://forward-rules-complex.test/api/v2/test", t),
			expected: false,
		},
		{
			name: "Rule matches by path prefix /old",
			rule: ForwardRule{
				Hostname: "old-service-backend.test",
				Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/old"}}},
			},
			req:      mustCreateRequest("GET", "https://forward-rules-complex.test/old/test", t),
			expected: true,
		},
		{
			name: "Rule does not match path without prefix",
			rule: ForwardRule{
				Hostname: "api-v1-backend.test",
				Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/api/v1"}}},
			},
			req:      mustCreateRequest("GET", "https://forward-rules-complex.test/old/test", t),
			expected: false,
		},
		{
			name: "Multiple rules - first matches",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules: rule.RequestRules{
					{URL: &rule.URLConditions{Exact: "https://example.com/path1"}},
					{URL: &rule.URLConditions{Exact: "https://example.com/path2"}},
				},
			},
			req:      mustCreateRequest("GET", "https://example.com/path1", t),
			expected: true,
		},
		{
			name: "Multiple rules - second matches",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules: rule.RequestRules{
					{URL: &rule.URLConditions{Exact: "https://example.com/path1"}},
					{URL: &rule.URLConditions{Exact: "https://example.com/path2"}},
				},
			},
			req:      mustCreateRequest("GET", "https://example.com/path2", t),
			expected: true,
		},
		{
			name: "Multiple rules - none matches",
			rule: ForwardRule{
				Hostname: "example.com",
				Rules: rule.RequestRules{
					{URL: &rule.URLConditions{Exact: "https://example.com/path1"}},
					{URL: &rule.URLConditions{Exact: "https://example.com/path2"}},
				},
			},
			req:      mustCreateRequest("GET", "https://example.com/path3", t),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Match(tt.req)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestForwardRules_Apply(t *testing.T) {
	tests := []struct {
		name         string
		rules        ForwardRules
		req          *http.Request
		expectedHost string
	}{
		{
			name:         "Empty rules returns empty string",
			rules:        ForwardRules{},
			req:          mustCreateRequest("GET", "https://example.com/path", t),
			expectedHost: "",
		},
		{
			name: "Single matching rule returns hostname",
			rules: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://example.com/path", t),
			expectedHost: "forward1.com",
		},
		{
			name: "First matching rule returns hostname",
			rules: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path"}}},
				},
				{
					Hostname: "forward2.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://example.com/path", t),
			expectedHost: "forward1.com",
		},
		{
			name: "No matching rules returns empty string",
			rules: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://other.com/path"}}},
				},
				{
					Hostname: "forward2.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://another.com/path"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://example.com/path", t),
			expectedHost: "",
		},
		{
			name: "Second matching rule returns hostname when first doesn't match",
			rules: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://other.com/path"}}},
				},
				{
					Hostname: "forward2.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://example.com/path", t),
			expectedHost: "forward2.com",
		},
		{
			name: "Nil rules matches everything and returns hostname",
			rules: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    nil,
				},
			},
			req:          mustCreateRequest("GET", "https://any.com/any", t),
			expectedHost: "forward1.com",
		},
		{
			name: "Empty rule in rules slice matches everything and returns hostname",
			rules: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{rule.EmptyRequestRule},
				},
			},
			req:          mustCreateRequest("GET", "https://any.com/any", t),
			expectedHost: "forward1.com",
		},
		{
			name: "Forward rule with /api/v1 prefix matches and returns hostname",
			rules: ForwardRules{
				{
					Hostname: "api-v1-backend.test",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/api/v1"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://forward-rules-complex.test/api/v1/test", t),
			expectedHost: "api-v1-backend.test",
		},
		{
			name: "Forward rule with /old prefix matches and returns hostname",
			rules: ForwardRules{
				{
					Hostname: "old-service-backend.test",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/old"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://forward-rules-complex.test/old/test", t),
			expectedHost: "old-service-backend.test",
		},
		{
			name: "Multiple forward rules - first prefix matches",
			rules: ForwardRules{
				{
					Hostname: "api-v1-backend.test",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/api/v1"}}},
				},
				{
					Hostname: "old-service-backend.test",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/old"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://forward-rules-complex.test/api/v1/test", t),
			expectedHost: "api-v1-backend.test",
		},
		{
			name: "Multiple forward rules - second prefix matches",
			rules: ForwardRules{
				{
					Hostname: "api-v1-backend.test",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/api/v1"}}},
				},
				{
					Hostname: "old-service-backend.test",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/old"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://forward-rules-complex.test/old/test", t),
			expectedHost: "old-service-backend.test",
		},
		{
			name: "Multiple forward rules - no prefix matches returns empty string",
			rules: ForwardRules{
				{
					Hostname: "api-v1-backend.test",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/api/v1"}}},
				},
				{
					Hostname: "old-service-backend.test",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Prefix: "/old"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://forward-rules-complex.test/api/v2/test", t),
			expectedHost: "",
		},
		{
			name: "Multiple rules with empty rule returns first hostname",
			rules: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{rule.EmptyRequestRule},
				},
				{
					Hostname: "forward2.com",
					Rules:    rule.RequestRules{rule.EmptyRequestRule},
				},
			},
			req:          mustCreateRequest("GET", "https://any.com/any", t),
			expectedHost: "forward1.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rules.Apply(tt.req)
			if result != tt.expectedHost {
				t.Errorf("Expected Apply() = %s, got %s", tt.expectedHost, result)
			}
		})
	}
}

func TestForwardRules_ApplyWithQueryParams(t *testing.T) {
	rules := ForwardRules{
		{
			Hostname: "forward1.com",
			Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path?key=value"}}},
		},
	}

	req := mustCreateRequest("GET", "https://example.com/path?key=value", t)
	result := rules.Apply(req)

	if result != "forward1.com" {
		t.Errorf("Expected Apply() = 'forward1.com', got %s", result)
	}

	// Test without query params - should not match
	req2 := mustCreateRequest("GET", "https://example.com/path", t)
	result2 := rules.Apply(req2)

	if result2 != "" {
		t.Errorf("Expected Apply() = '' for non-matching URL, got %s", result2)
	}
}

func TestForwardRule_JSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want ForwardRule
	}{
		{
			name: "Forward rule with hostname and rules",
			json: `{"hostname":"example.com","rules":[{"url":{"exact":"https://original.com/path"}}]}`,
			want: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://original.com/path"}}},
			},
		},
		{
			name: "Forward rule with empty rules",
			json: `{"hostname":"example.com","rules":[]}`,
			want: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{},
			},
		},
		{
			name: "Forward rule with multiple rules",
			json: `{"hostname":"example.com","rules":[{"url":{"exact":"https://original.com/path"}},{"methods":["POST"]}]}`,
			want: ForwardRule{
				Hostname: "example.com",
				Rules: rule.RequestRules{
					{URL: &rule.URLConditions{Exact: "https://original.com/path"}},
					{Methods: []string{"POST"}},
				},
			},
		},
		{
			name: "Forward rule with query parameters",
			json: `{"hostname":"example.com","rules":[{"url":{"exact":"https://original.com/path?key=value"}}]}`,
			want: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://original.com/path?key=value"}}},
			},
		},
		{
			name: "Forward rule with new features - methods and path",
			json: `{"hostname":"example.com","rules":[{"methods":["GET","POST"],"path":{"exact":"/api"}}]}`,
			want: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{{Methods: []string{"GET", "POST"}, Path: &rule.PathConditions{Exact: "/api"}}},
			},
		},
		{
			name: "Forward rule with IP matching",
			json: `{"hostname":"example.com","rules":[{"ip":{"ips":["192.168.1.1"],"cidrs":["10.0.0.0/8"]}}]}`,
			want: ForwardRule{
				Hostname: "example.com",
				Rules:    rule.RequestRules{{IP: &rule.IPConditions{IPs: []string{"192.168.1.1"}, CIDRs: []string{"10.0.0.0/8"}}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshaling from JSON
			var got ForwardRule
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}
			if got.Hostname != tt.want.Hostname {
				t.Errorf("Expected Hostname=%s, got %s", tt.want.Hostname, got.Hostname)
			}
			if len(got.Rules) != len(tt.want.Rules) {
				t.Errorf("Expected %d rules, got %d", len(tt.want.Rules), len(got.Rules))
			}
			for i := range got.Rules {
				// Compare URL conditions
				if got.Rules[i].URL == nil && tt.want.Rules[i].URL == nil {
					// Both nil, skip
				} else if got.Rules[i].URL == nil || tt.want.Rules[i].URL == nil {
					t.Errorf("Rule %d: Expected URL nil=%v, got nil=%v", i, tt.want.Rules[i].URL == nil, got.Rules[i].URL == nil)
				} else if got.Rules[i].URL.Exact != tt.want.Rules[i].URL.Exact {
					t.Errorf("Rule %d: Expected URL.Exact=%s, got %s", i, tt.want.Rules[i].URL.Exact, got.Rules[i].URL.Exact)
				}
				if len(got.Rules[i].Methods) != len(tt.want.Rules[i].Methods) {
					t.Errorf("Rule %d: Expected %d methods, got %d", i, len(tt.want.Rules[i].Methods), len(got.Rules[i].Methods))
				}
			}

			// Test marshaling to JSON
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Failed to marshal JSON: %v", err)
			}

			// Unmarshal again to verify round-trip
			var roundTrip ForwardRule
			if err := json.Unmarshal(data, &roundTrip); err != nil {
				t.Fatalf("Failed to unmarshal round-trip JSON: %v", err)
			}
			if roundTrip.Hostname != tt.want.Hostname {
				t.Errorf("Round-trip failed: Expected Hostname=%s, got %s", tt.want.Hostname, roundTrip.Hostname)
			}
			if len(roundTrip.Rules) != len(tt.want.Rules) {
				t.Errorf("Round-trip failed: Expected %d rules, got %d", len(tt.want.Rules), len(roundTrip.Rules))
			}
		})
	}
}

func TestForwardRules_JSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want ForwardRules
	}{
		{
			name: "Single forward rule",
			json: `[{"hostname":"forward1.com","rules":[{"url":{"exact":"https://example.com/path1"}}]}]`,
			want: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path1"}}},
				},
			},
		},
		{
			name: "Multiple forward rules",
			json: `[{"hostname":"forward1.com","rules":[{"url":{"exact":"https://example.com/path1"}}]},{"hostname":"forward2.com","rules":[{"url":{"exact":"https://example.com/path2"}}]}]`,
			want: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path1"}}},
				},
				{
					Hostname: "forward2.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path2"}}},
				},
			},
		},
		{
			name: "Empty forward rules",
			json: `[]`,
			want: ForwardRules{},
		},
		{
			name: "Rules with empty rules slice",
			json: `[{"hostname":"forward1.com","rules":[]},{"hostname":"forward2.com","rules":[{"url":{"exact":"https://example.com/path"}}]}]`,
			want: ForwardRules{
				{
					Hostname: "forward1.com",
					Rules:    rule.RequestRules{},
				},
				{
					Hostname: "forward2.com",
					Rules:    rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/path"}}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshaling from JSON
			var got ForwardRules
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Expected %d rules, got %d", len(tt.want), len(got))
			}
			for i := range got {
				if got[i].Hostname != tt.want[i].Hostname {
					t.Errorf("Rule %d: Expected Hostname=%s, got %s", i, tt.want[i].Hostname, got[i].Hostname)
				}
				if len(got[i].Rules) != len(tt.want[i].Rules) {
					t.Errorf("Rule %d: Expected %d request rules, got %d", i, len(tt.want[i].Rules), len(got[i].Rules))
				}
			}

			// Test marshaling to JSON
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Failed to marshal JSON: %v", err)
			}

			// Unmarshal again to verify round-trip
			var roundTrip ForwardRules
			if err := json.Unmarshal(data, &roundTrip); err != nil {
				t.Fatalf("Failed to unmarshal round-trip JSON: %v", err)
			}
			if len(roundTrip) != len(tt.want) {
				t.Fatalf("Round-trip failed: Expected %d rules, got %d", len(tt.want), len(roundTrip))
			}
		})
	}
}

func mustCreateRequest(method, rawURL string, t *testing.T) *http.Request {
	t.Helper()
	return mustCreateRequestWithHeaders(method, rawURL, nil, t)
}

func mustCreateRequestWithHeaders(method, rawURL string, headers map[string]string, t *testing.T) *http.Request {
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
	// Initialize request data
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

func mustCreateRequestWithRemoteAddr(method, rawURL, remoteAddr string, t *testing.T) *http.Request {
	t.Helper()
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Failed to parse URL %s: %v", rawURL, err)
	}
	req := &http.Request{
		Method:     method,
		URL:        parsedURL,
		Header:     make(http.Header),
		RemoteAddr: remoteAddr,
	}
	// Initialize request data
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))
	return req
}

func TestForwardRules_ApplyWithNewFeatures(t *testing.T) {
	tests := []struct {
		name         string
		rules        ForwardRules
		req          *http.Request
		expectedHost string
	}{
		{
			name: "Match by methods",
			rules: ForwardRules{
				{
					Hostname: "method-match.com",
					Rules:    rule.RequestRules{{Methods: []string{"POST"}}},
				},
			},
			req:          mustCreateRequest("POST", "https://example.com/path", t),
			expectedHost: "method-match.com",
		},
		{
			name: "Match by path contains",
			rules: ForwardRules{
				{
					Hostname: "path-match.com",
					Rules:    rule.RequestRules{{Path: &rule.PathConditions{Contains: "/api"}}},
				},
			},
			req:          mustCreateRequest("GET", "https://example.com/api/users", t),
			expectedHost: "path-match.com",
		},
		{
			name: "Match by headers",
			rules: ForwardRules{
				{
					Hostname: "header-match.com",
					Rules:    rule.RequestRules{{Headers: &rule.HeaderConditions{Exact: map[string]string{"Authorization": "Bearer token"}}}},
				},
			},
			req:          mustCreateRequestWithHeaders("GET", "https://example.com/path", map[string]string{"Authorization": "Bearer token"}, t),
			expectedHost: "header-match.com",
		},
		{
			name: "Match by query parameters",
			rules: ForwardRules{
				{
					Hostname: "query-match.com",
					Rules:    rule.RequestRules{{Query: &rule.QueryConditions{Exact: map[string]string{"key": "value"}}}},
				},
			},
			req:          mustCreateRequest("GET", "https://example.com/path?key=value", t),
			expectedHost: "query-match.com",
		},
		{
			name: "Match by IP address",
			rules: ForwardRules{
				{
					Hostname: "ip-match.com",
					Rules:    rule.RequestRules{{IP: &rule.IPConditions{IPs: []string{"192.168.1.1"}}}},
				},
			},
			req:          mustCreateRequestWithRemoteAddr("GET", "https://example.com/path", "192.168.1.1:12345", t),
			expectedHost: "ip-match.com",
		},
		{
			name: "Match by CIDR range",
			rules: ForwardRules{
				{
					Hostname: "cidr-match.com",
					Rules:    rule.RequestRules{{IP: &rule.IPConditions{CIDRs: []string{"192.168.1.0/24"}}}},
				},
			},
			req:          mustCreateRequestWithRemoteAddr("GET", "https://example.com/path", "192.168.1.100:12345", t),
			expectedHost: "cidr-match.com",
		},
		{
			name: "Match by X-Real-IP header",
			rules: ForwardRules{
				{
					Hostname: "xrealip-match.com",
					Rules:    rule.RequestRules{{IP: &rule.IPConditions{IPs: []string{"10.0.0.1"}}}},
				},
			},
			req: func() *http.Request {
				req := mustCreateRequestWithRemoteAddr("GET", "https://example.com/path", "192.168.1.1:12345", t)
				req.Header.Set("X-Real-IP", "10.0.0.1")
				return req
			}(),
			expectedHost: "xrealip-match.com",
		},
		{
			name: "Match by GeoIP country code",
			rules: ForwardRules{
				{
					Hostname: "geoip-match.com",
					Rules: rule.RequestRules{{
						Location: &rule.LocationConditions{CountryCodes: []string{"US"}},
					}},
				},
			},
			req: func() *http.Request {
				req := mustCreateRequest("GET", "https://example.com/path", t)
				requestData := reqctx.GetRequestData(req.Context())
				if requestData == nil {
					requestData = reqctx.NewRequestData()
					req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))
				}
				requestData.Location = &reqctx.Location{
					CountryCode: "US",
				}
				return req
			}(),
			expectedHost: "geoip-match.com",
		},
		{
			name: "Match by UAParser user agent family",
			rules: ForwardRules{
				{
					Hostname: "uaparser-match.com",
					Rules: rule.RequestRules{{
						UserAgent: &rule.UserAgentConditions{UserAgentFamilies: []string{"Chrome"}},
					}},
				},
			},
			req: func() *http.Request {
				req := mustCreateRequest("GET", "https://example.com/path", t)
				requestData := reqctx.GetRequestData(req.Context())
				if requestData == nil {
					requestData = reqctx.NewRequestData()
					req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))
				}
				requestData.UserAgent = &reqctx.UserAgent{
					Family: "Chrome",
				}
				return req
			}(),
			expectedHost: "uaparser-match.com",
		},
		{
			name: "Multiple rules - AND logic within rule, OR logic across rules",
			rules: ForwardRules{
				{
					Hostname: "and-or-match.com",
					Rules: rule.RequestRules{
						{Methods: []string{"POST"}, Path: &rule.PathConditions{Contains: "/api"}},
						{IP: &rule.IPConditions{IPs: []string{"192.168.1.1"}}},
					},
				},
			},
			req:          mustCreateRequestWithRemoteAddr("POST", "https://example.com/api/users", "192.168.1.1:12345", t),
			expectedHost: "and-or-match.com",
		},
		{
			name: "Complex rule - methods AND path AND headers",
			rules: ForwardRules{
				{
					Hostname: "complex-match.com",
					Rules: rule.RequestRules{{
						Methods: []string{"POST"},
						Path:    &rule.PathConditions{Exact: "/api/users"},
						Headers: &rule.HeaderConditions{Exact: map[string]string{"Content-Type": "application/json"}},
					}},
				},
			},
			req:          mustCreateRequestWithHeaders("POST", "https://example.com/api/users", map[string]string{"Content-Type": "application/json"}, t),
			expectedHost: "complex-match.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rules.Apply(tt.req)
			if result != tt.expectedHost {
				t.Errorf("Expected Apply() = %s, got %s", tt.expectedHost, result)
			}
		})
	}
}
