package rule

import (
	"testing"
)

func BenchmarkRequestRule_Match_Simple(b *testing.B) {
	b.ReportAllocs()
	rule := RequestRule{
		Methods: []string{"GET"},
		Path:    &PathConditions{Exact: "/api/users"},
	}
	req := mustCreateRequest("GET", "https://example.com/api/users", b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Match(req)
	}
}

func BenchmarkRequestRule_Match_Complex(b *testing.B) {
	b.ReportAllocs()
	rule := RequestRule{
		Methods: []string{"GET", "POST"},
		Path:    &PathConditions{Contains: "/api"},
		Scheme:   "https",
		Headers: &HeaderConditions{
			Exact:  map[string]string{"Content-Type": "application/json"},
			Exists: []string{"Authorization"},
		},
		Query: &QueryConditions{
			Exact: map[string]string{"key": "value"},
		},
		ContentTypes: []string{"application/json"},
		IP: &IPConditions{
			IPs:   []string{"192.168.1.1"},
			CIDRs: []string{"10.0.0.0/8"},
		},
	}
	req := mustCreateRequestWithHeaders("GET", "https://example.com/api/users?key=value", map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer token",
	}, b)
	req.RemoteAddr = "192.168.1.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Match(req)
	}
}

// BenchmarkRequestRule_Match_User - Disabled (user package removed)
// func BenchmarkRequestRule_Match_User(b *testing.B) {
// 	rule := RequestRule{
// 		AuthConditions: &AuthConditions{
// 			{
// 				AuthConditionRules: []AuthConditionRule{
// 					{
// 						Path:   "role",
// 						Values: []string{"admin", "editor"},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	req := mustCreateRequest("GET", "https://example.com/path", b)
// 
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_ = rule.Match(req)
// 	}
// }

// Temporarily disabled due to refactoring
/*
func BenchmarkRequestRule_Match_MaxMind(b *testing.B) {
	b.ReportAllocs()
	rule := RequestRule{
		MaxMind: &MaxMindRule{
			CountryCodes:   []string{"US", "GB"},
			ContinentCodes: []string{"NA", "EU"},
		},
	}
	req := mustCreateRequest("GET", "https://example.com/path", b)
	location := &libmaxmind.Result{
		CountryCode:   "US",
		ContinentCode: "NA",
	}
	maxmind.Put(req, location)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Match(req)
	}
}
*/

// Temporarily disabled due to refactoring
/*
func BenchmarkRequestRule_Match_UAParser(b *testing.B) {
	b.ReportAllocs()
	rule := RequestRule{
		UAParser: &UAParserRule{
			UserAgentFamilies: []string{"Chrome", "Firefox"},
			OSFamilies:        []string{"Windows", "Mac OS X"},
		},
	}
	req := mustCreateRequest("GET", "https://example.com/path", b)
	uaResult := &libuaparser.Result{
		UserAgent: &uaparser.UserAgent{Family: "Chrome"},
		OS:        &uaparser.Os{Family: "Windows"},
	}
	internaluaparser.Put(req, uaResult)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.Match(req)
	}
}
*/

func BenchmarkRequestRules_Match(b *testing.B) {
	b.ReportAllocs()
	rules := RequestRules{
		RequestRule{Methods: []string{"GET"}, Path: &PathConditions{Exact: "/api/users"}},
		RequestRule{Methods: []string{"POST"}, Path: &PathConditions{Exact: "/api/posts"}},
		RequestRule{Methods: []string{"PUT"}, Path: &PathConditions{Contains: "/api"}},
	}
	req := mustCreateRequest("GET", "https://example.com/api/users", b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rules.Match(req)
	}
}

// BenchmarkUserConditions_match - Disabled (user package removed)
// func BenchmarkUserConditions_match(b *testing.B) {
// 	conditions := AuthConditions{
// 		{
// 			AuthConditionRules: []AuthConditionRule{
// 				{
// 					Path:   "roles",
// 					Values: []string{"admin", "editor", "viewer"},
// 				},
// 			},
// 		},
// 	}
// 	authData := &reqctx.AuthData{
// 		Type: "oauth",
// 		Data: map[string]any{
// 			"roles": []string{"admin", "editor", "viewer"},
// 		},
// 	}
// 
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_ = conditions.match(authData)
// 	}
// }

func BenchmarkMatchesIPOrCIDR(b *testing.B) {
	b.ReportAllocs()
	clientIP := "192.168.1.100"
	ipOrCIDRs := []string{
		"192.168.1.1",
		"192.168.1.0/24",
		"10.0.0.0/8",
		"172.16.0.0/12",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchesIPOrCIDR(clientIP, ipOrCIDRs)
	}
}

