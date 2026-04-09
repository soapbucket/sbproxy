package rule

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func BenchmarkRequestRule_Match_Location(b *testing.B) {
	b.ReportAllocs()
	rule := RequestRule{
		Location: &LocationConditions{
			CountryCodes:   []string{"US", "GB", "FR", "DE"},
			ContinentCodes: []string{"NA", "EU"},
		},
	}
	
	req := mustCreateRequest("GET", "https://example.com/path", b)
	
	// Add location data to request context
	reqData := reqctx.NewRequestData()
	reqData.Location = &reqctx.Location{
		CountryCode:   "US",
		Country:       "United States",
		ContinentCode: "NA",
		Continent:     "North America",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Match(req)
	}
}

func BenchmarkRequestRule_Match_UserAgent(b *testing.B) {
	b.ReportAllocs()
	rule := RequestRule{
		UserAgent: &UserAgentConditions{
			UserAgentFamilies: []string{"Chrome", "Firefox", "Safari"},
			OSFamilies:        []string{"Windows", "Mac OS X", "Linux"},
		},
	}
	
	req := mustCreateRequest("GET", "https://example.com/path", b)
	
	// Add user agent data to request context
	reqData := reqctx.NewRequestData()
	reqData.UserAgent = &reqctx.UserAgent{
		Family:   "Chrome",
		Major:    "120",
		OSFamily: "Windows",
		OSMajor:  "10",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Match(req)
	}
}

func BenchmarkRequestRule_Match_AuthConditions(b *testing.B) {
	b.ReportAllocs()
	rule := RequestRule{
		AuthConditions: &AuthConditions{
			{
				Type: "oauth",
				AuthConditionRules: []AuthConditionRule{
					{
						Path:  "email",
						Value: "admin@example.com",
					},
					{
						Path:   "roles.0",
						Values: []string{"admin", "superuser"},
					},
				},
			},
		},
	}
	
	req := mustCreateRequest("GET", "https://example.com/path", b)
	
	// Add auth data to request context
	reqData := reqctx.NewRequestData()
	reqData.SessionData = &reqctx.SessionData{
		AuthData: &reqctx.AuthData{
			Type: "oauth",
			Data: map[string]any{
				"email": "admin@example.com",
				"roles": []any{"admin", "user"},
			},
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Match(req)
	}
}

func BenchmarkRequestRule_Match_Combined(b *testing.B) {
	b.ReportAllocs()
	rule := RequestRule{
		Methods: []string{"GET", "POST"},
		Location: &LocationConditions{
			CountryCodes: []string{"US", "GB"},
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
	
	req := mustCreateRequest("GET", "https://example.com/path", b)
	
	// Add all data to request context
	reqData := reqctx.NewRequestData()
	reqData.Location = &reqctx.Location{
		CountryCode: "US",
	}
	reqData.UserAgent = &reqctx.UserAgent{
		Family: "Chrome",
	}
	reqData.SessionData = &reqctx.SessionData{
		AuthData: &reqctx.AuthData{
			Type: "oauth",
			Data: map[string]any{
				"email": "admin@example.com",
			},
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Match(req)
	}
}

