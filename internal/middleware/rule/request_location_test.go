package rule

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestRequestRule_Match_Location(t *testing.T) {
	tests := []struct {
		name     string
		rule     RequestRule
		location *reqctx.Location
		expected bool
	}{
		{
			name: "Country code matches",
			rule: RequestRule{
				Location: &LocationConditions{
					CountryCodes: []string{"US", "GB"},
				},
			},
			location: &reqctx.Location{
				CountryCode: "US",
			},
			expected: true,
		},
		{
			name: "Country code does not match",
			rule: RequestRule{
				Location: &LocationConditions{
					CountryCodes: []string{"US", "GB"},
				},
			},
			location: &reqctx.Location{
				CountryCode: "FR",
			},
			expected: false,
		},
		{
			name: "Country name matches",
			rule: RequestRule{
				Location: &LocationConditions{
					Countries: []string{"United States", "United Kingdom"},
				},
			},
			location: &reqctx.Location{
				Country: "United States",
			},
			expected: true,
		},
		{
			name: "Continent code matches",
			rule: RequestRule{
				Location: &LocationConditions{
					ContinentCodes: []string{"NA", "EU"},
				},
			},
			location: &reqctx.Location{
				ContinentCode: "NA",
			},
			expected: true,
		},
		{
			name: "ASN matches",
			rule: RequestRule{
				Location: &LocationConditions{
					ASNs: []string{"AS15169", "AS13335"},
				},
			},
			location: &reqctx.Location{
				ASN: "AS15169",
			},
			expected: true,
		},
		{
			name: "Multiple conditions - all match",
			rule: RequestRule{
				Location: &LocationConditions{
					CountryCodes:   []string{"US"},
					ContinentCodes: []string{"NA"},
				},
			},
			location: &reqctx.Location{
				CountryCode:   "US",
				ContinentCode: "NA",
			},
			expected: true,
		},
		{
			name: "Multiple conditions - one fails",
			rule: RequestRule{
				Location: &LocationConditions{
					CountryCodes:   []string{"US"},
					ContinentCodes: []string{"EU"},
				},
			},
			location: &reqctx.Location{
				CountryCode:   "US",
				ContinentCode: "NA",
			},
			expected: false,
		},
		{
			name:     "Nil location when required",
			rule:     RequestRule{Location: &LocationConditions{CountryCodes: []string{"US"}}},
			location: nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mustCreateRequest("GET", "https://example.com/path", t)
			
			// Add location data to request context
			reqData := reqctx.NewRequestData()
			reqData.Location = tt.location
			req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))

			result := tt.rule.Match(req)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRequestRule_Match_UserAgent(t *testing.T) {
	tests := []struct {
		name      string
		rule      RequestRule
		userAgent *reqctx.UserAgent
		expected  bool
	}{
		{
			name: "Browser family matches",
			rule: RequestRule{
				UserAgent: &UserAgentConditions{
					UserAgentFamilies: []string{"Chrome", "Firefox"},
				},
			},
			userAgent: &reqctx.UserAgent{
				Family: "Chrome",
			},
			expected: true,
		},
		{
			name: "Browser family does not match",
			rule: RequestRule{
				UserAgent: &UserAgentConditions{
					UserAgentFamilies: []string{"Chrome", "Firefox"},
				},
			},
			userAgent: &reqctx.UserAgent{
				Family: "Safari",
			},
			expected: false,
		},
		{
			name: "OS family matches",
			rule: RequestRule{
				UserAgent: &UserAgentConditions{
					OSFamilies: []string{"Windows", "Mac OS X"},
				},
			},
			userAgent: &reqctx.UserAgent{
				OSFamily: "Windows",
			},
			expected: true,
		},
		{
			name: "Device family matches",
			rule: RequestRule{
				UserAgent: &UserAgentConditions{
					DeviceFamilies: []string{"iPhone", "iPad"},
				},
			},
			userAgent: &reqctx.UserAgent{
				DeviceFamily: "iPhone",
			},
			expected: true,
		},
		{
			name: "Multiple conditions - all match",
			rule: RequestRule{
				UserAgent: &UserAgentConditions{
					UserAgentFamilies: []string{"Chrome"},
					OSFamilies:        []string{"Windows"},
				},
			},
			userAgent: &reqctx.UserAgent{
				Family:   "Chrome",
				OSFamily: "Windows",
			},
			expected: true,
		},
		{
			name: "Multiple conditions - one fails",
			rule: RequestRule{
				UserAgent: &UserAgentConditions{
					UserAgentFamilies: []string{"Chrome"},
					OSFamilies:        []string{"Mac OS X"},
				},
			},
			userAgent: &reqctx.UserAgent{
				Family:   "Chrome",
				OSFamily: "Windows",
			},
			expected: false,
		},
		{
			name:      "Nil user agent when required",
			rule:      RequestRule{UserAgent: &UserAgentConditions{UserAgentFamilies: []string{"Chrome"}}},
			userAgent: nil,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mustCreateRequest("GET", "https://example.com/path", t)
			
			// Add user agent data to request context
			reqData := reqctx.NewRequestData()
			reqData.UserAgent = tt.userAgent
			req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))

			result := tt.rule.Match(req)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRequestRule_Match_AuthConditions(t *testing.T) {
	tests := []struct {
		name     string
		rule     RequestRule
		authData *reqctx.AuthData
		expected bool
	}{
		{
			name: "Auth type and email match",
			rule: RequestRule{
				AuthConditions: &AuthConditions{
					{
						Type: "oauth",
						AuthConditionRules: []AuthConditionRule{
							{
								Path:  "email",
								Value: "admin@example.com",
							},
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "admin@example.com",
					"roles": []any{"admin"},
				},
			},
			expected: true,
		},
		{
			name: "Auth type matches but data doesn't",
			rule: RequestRule{
				AuthConditions: &AuthConditions{
					{
						Type: "oauth",
						AuthConditionRules: []AuthConditionRule{
							{
								Path:  "email",
								Value: "admin@example.com",
							},
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "user@example.com",
				},
			},
			expected: false,
		},
		{
			name: "Role contains check",
			rule: RequestRule{
				AuthConditions: &AuthConditions{
					{
						Type: "oauth",
						AuthConditionRules: []AuthConditionRule{
							{
								Path:     "roles.0",
								Contains: "admin",
							},
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"roles": []any{"admin", "user"},
				},
			},
			expected: true,
		},
		{
			name: "Multiple auth conditions (OR logic)",
			rule: RequestRule{
				AuthConditions: &AuthConditions{
					{
						Type: "oauth",
						AuthConditionRules: []AuthConditionRule{
							{Path: "email", Value: "admin@example.com"},
						},
					},
					{
						Type: "jwt",
						AuthConditionRules: []AuthConditionRule{
							{Path: "sub", Value: "user123"},
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "jwt",
				Data: map[string]any{
					"sub": "user123",
				},
			},
			expected: true,
		},
		{
			name: "Nil auth data when required",
			rule: RequestRule{
				AuthConditions: &AuthConditions{
					{
						Type: "oauth",
						AuthConditionRules: []AuthConditionRule{
							{Path: "email", Value: "admin@example.com"},
						},
					},
				},
			},
			authData: nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mustCreateRequest("GET", "https://example.com/path", t)
			
			// Add auth data to request context
			reqData := reqctx.NewRequestData()
			if tt.authData != nil {
				reqData.SessionData = &reqctx.SessionData{
					AuthData: tt.authData,
				}
			}
			req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))

			result := tt.rule.Match(req)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRequestRule_Match_Combined_Conditions(t *testing.T) {
	// Test combining location, user agent, and auth conditions
	rule := RequestRule{
		Methods: []string{"GET"},
		Location: &LocationConditions{
			CountryCodes: []string{"US"},
		},
		UserAgent: &UserAgentConditions{
			UserAgentFamilies: []string{"Chrome"},
		},
		AuthConditions: &AuthConditions{
			{
				Type: "oauth",
				AuthConditionRules: []AuthConditionRule{
					{Path: "email", Value: "admin@example.com"},
				},
			},
		},
	}

	tests := []struct {
		name      string
		method    string
		location  *reqctx.Location
		userAgent *reqctx.UserAgent
		authData  *reqctx.AuthData
		expected  bool
	}{
		{
			name:   "All conditions match",
			method: "GET",
			location: &reqctx.Location{
				CountryCode: "US",
			},
			userAgent: &reqctx.UserAgent{
				Family: "Chrome",
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{"email": "admin@example.com"},
			},
			expected: true,
		},
		{
			name:   "Wrong method",
			method: "POST",
			location: &reqctx.Location{
				CountryCode: "US",
			},
			userAgent: &reqctx.UserAgent{
				Family: "Chrome",
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{"email": "admin@example.com"},
			},
			expected: false,
		},
		{
			name:   "Wrong location",
			method: "GET",
			location: &reqctx.Location{
				CountryCode: "FR",
			},
			userAgent: &reqctx.UserAgent{
				Family: "Chrome",
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{"email": "admin@example.com"},
			},
			expected: false,
		},
		{
			name:   "Wrong user agent",
			method: "GET",
			location: &reqctx.Location{
				CountryCode: "US",
			},
			userAgent: &reqctx.UserAgent{
				Family: "Firefox",
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{"email": "admin@example.com"},
			},
			expected: false,
		},
		{
			name:   "Wrong auth data",
			method: "GET",
			location: &reqctx.Location{
				CountryCode: "US",
			},
			userAgent: &reqctx.UserAgent{
				Family: "Chrome",
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{"email": "user@example.com"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mustCreateRequest(tt.method, "https://example.com/path", t)
			
			// Add all data to request context
			reqData := reqctx.NewRequestData()
			reqData.Location = tt.location
			reqData.UserAgent = tt.userAgent
			if tt.authData != nil {
				reqData.SessionData = &reqctx.SessionData{
					AuthData: tt.authData,
				}
			}
			req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))

			result := rule.Match(req)
			if result != tt.expected {
				t.Errorf("Expected Match() = %v, got %v", tt.expected, result)
			}
		})
	}
}

