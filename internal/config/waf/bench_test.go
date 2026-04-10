package waf

import (
	"context"
	"net/http/httptest"
	"testing"
)

// BenchmarkWAFRuleEngine_SimpleRule benchmarks a simple WAF rule evaluation
func BenchmarkWAFRuleEngine_SimpleRule(b *testing.B) {
	b.ReportAllocs()
	rules := []WAFRule{
		{
			ID:      "test-001",
			Enabled: true,
			Phase:   2,
			Action:  "block",
			Variables: []WAFVariable{
				{Name: "ARGS"},
			},
			Operator: "rx",
			Pattern:  "(?i)(union|select)",
		},
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?q=SELECT+*+FROM+users", nil)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.EvaluateRequest(ctx, req)
	}
}

// BenchmarkWAFRuleEngine_NoMatch benchmarks WAF rule evaluation with no matches
func BenchmarkWAFRuleEngine_NoMatch(b *testing.B) {
	b.ReportAllocs()
	rules := []WAFRule{
		{
			ID:      "test-001",
			Enabled: true,
			Phase:   2,
			Action:  "block",
			Variables: []WAFVariable{
				{Name: "ARGS"},
			},
			Operator: "rx",
			Pattern:  "(?i)(union|select)",
		},
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?q=hello+world", nil)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.EvaluateRequest(ctx, req)
	}
}

// BenchmarkWAFRuleEngine_MultipleRules benchmarks evaluation with multiple rules
func BenchmarkWAFRuleEngine_MultipleRules(b *testing.B) {
	b.ReportAllocs()
	rules := []WAFRule{
		{
			ID:      "rule-001",
			Enabled: true,
			Phase:   1,
			Action:  "log",
			Variables: []WAFVariable{
				{Name: "REQUEST_URI"},
			},
			Operator: "rx",
			Pattern:  "(?i)/admin",
		},
		{
			ID:      "rule-002",
			Enabled: true,
			Phase:   2,
			Action:  "block",
			Variables: []WAFVariable{
				{Name: "ARGS"},
			},
			Operator: "rx",
			Pattern:  "(?i)(union|select|drop|delete)",
		},
		{
			ID:      "rule-003",
			Enabled: true,
			Phase:   2,
			Action:  "block",
			Variables: []WAFVariable{
				{Name: "REQUEST_HEADERS"},
			},
			Operator: "contains",
			Pattern:  "<script>",
		},
		{
			ID:      "rule-004",
			Enabled: true,
			Phase:   3,
			Action:  "log",
			Variables: []WAFVariable{
				{Name: "REQUEST_METHOD"},
			},
			Operator: "eq",
			Pattern:  "POST",
		},
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/api/users?q=test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.EvaluateRequest(ctx, req)
	}
}

// BenchmarkWAFRuleEngine_WithTransformations benchmarks rules with transformations
func BenchmarkWAFRuleEngine_WithTransformations(b *testing.B) {
	b.ReportAllocs()
	rules := []WAFRule{
		{
			ID:      "rule-transform",
			Enabled: true,
			Phase:   2,
			Action:  "block",
			Variables: []WAFVariable{
				{
					Name:            "ARGS",
					Transformations: []string{"lowercase", "urlDecode"},
				},
			},
			Transformations: []string{"lowercase"},
			Operator:        "rx",
			Pattern:         "(?i)(union|select)",
		},
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?q=SELECT+*+FROM+users", nil)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.EvaluateRequest(ctx, req)
	}
}

// BenchmarkWAFRuleEngine_DisabledRules benchmarks with disabled rules (should be fast)
func BenchmarkWAFRuleEngine_DisabledRules(b *testing.B) {
	b.ReportAllocs()
	rules := []WAFRule{
		{
			ID:      "rule-disabled",
			Enabled: false,
			Phase:   2,
			Action:  "block",
			Variables: []WAFVariable{
				{Name: "ARGS"},
			},
			Operator: "rx",
			Pattern:  "(?i)(union|select)",
		},
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?q=SELECT+*+FROM+users", nil)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.EvaluateRequest(ctx, req)
	}
}

// BenchmarkExtractVariables benchmarks variable extraction
func BenchmarkExtractVariables(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/test?param1=value1&param2=value2", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Authorization", "Bearer token123")

	variable := WAFVariable{
		Name: "ARGS",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ExtractVariables(req, variable)
	}
}

// BenchmarkExtractVariables_Headers benchmarks header variable extraction
func BenchmarkExtractVariables_Headers(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("Content-Type", "application/json")

	variable := WAFVariable{
		Name: "REQUEST_HEADERS",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ExtractVariables(req, variable)
	}
}

// BenchmarkExtractVariables_WithTransformations benchmarks variable extraction with transformations
func BenchmarkExtractVariables_WithTransformations(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/test?q=SELECT+*+FROM+users", nil)

	variable := WAFVariable{
		Name:            "ARGS",
		Transformations: []string{"lowercase", "urlDecode"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ExtractVariables(req, variable)
	}
}

// BenchmarkApplyTransformations benchmarks transformation functions
func BenchmarkApplyTransformations(b *testing.B) {
	b.ReportAllocs()
	input := "SELECT+*+FROM+users%20WHERE%20id%3D1"
	transformations := []string{"lowercase", "urlDecode", "htmlEntityDecode"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ApplyTransformations(input, transformations)
	}
}

// BenchmarkMatchOperator benchmarks operator matching
func BenchmarkMatchOperator(b *testing.B) {
	b.ReportAllocs()
	value := "SELECT * FROM users WHERE id=1"
	pattern := "(?i)(union|select)"
	operator := "rx"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = MatchOperator(value, pattern, operator)
	}
}

// BenchmarkMatchOperator_PhraseMatch benchmarks phrase matching
func BenchmarkMatchOperator_PhraseMatch(b *testing.B) {
	b.ReportAllocs()
	value := "SELECT * FROM users WHERE id=1"
	pattern := "SELECT"
	operator := "pm"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = MatchOperator(value, pattern, operator)
	}
}

// BenchmarkMatchOperator_Contains benchmarks contains matching
func BenchmarkMatchOperator_Contains(b *testing.B) {
	b.ReportAllocs()
	value := "SELECT * FROM users WHERE id=1"
	pattern := "SELECT"
	operator := "contains"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = MatchOperator(value, pattern, operator)
	}
}

// BenchmarkParseModSecurityRule benchmarks ModSecurity rule parsing
func BenchmarkParseModSecurityRule(b *testing.B) {
	b.ReportAllocs()
	ruleStr := `SecRule ARGS "@rx (?i)(union|select)" "id:1001,phase:2,deny,status:403,msg:'SQL injection detected'"`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseModSecurityRule(ruleStr)
	}
}

// BenchmarkParseModSecurityRules benchmarks parsing multiple ModSecurity rules
func BenchmarkParseModSecurityRules(b *testing.B) {
	b.ReportAllocs()
	rules := []string{
		`SecRule ARGS "@rx (?i)(union|select)" "id:1001,phase:2,deny,status:403,msg:'SQL injection'"`,
		`SecRule REQUEST_URI "@rx /admin" "id:1002,phase:1,log,msg:'Admin access'"`,
		`SecRule REQUEST_HEADERS "@contains <script>" "id:1003,phase:2,deny,status:403,msg:'XSS attempt'"`,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseModSecurityRules(rules)
	}
}

// BenchmarkWAFRuleEngine_Concurrent benchmarks concurrent rule evaluation
func BenchmarkWAFRuleEngine_Concurrent(b *testing.B) {
	b.ReportAllocs()
	rules := []WAFRule{
		{
			ID:      "rule-001",
			Enabled: true,
			Phase:   2,
			Action:  "block",
			Variables: []WAFVariable{
				{Name: "ARGS"},
			},
			Operator: "rx",
			Pattern:  "(?i)(union|select)",
		},
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?q=SELECT+*+FROM+users", nil)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = engine.EvaluateRequest(ctx, req)
		}
	})
}

// BenchmarkWAFRuleEngine_LargeRuleSet benchmarks with a large number of rules
func BenchmarkWAFRuleEngine_LargeRuleSet(b *testing.B) {
	b.ReportAllocs()
	// Create 50 rules
	rules := make([]WAFRule, 50)
	for i := 0; i < 50; i++ {
		rules[i] = WAFRule{
			ID:      string(rune('0' + i%10)),
			Enabled: true,
			Phase:   (i % 5) + 1,
			Action:  "block",
			Variables: []WAFVariable{
				{Name: "ARGS"},
			},
			Operator: "rx",
			Pattern:  "(?i)(union|select|drop|delete|insert|update)",
		}
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?q=hello", nil)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.EvaluateRequest(ctx, req)
	}
}

// BenchmarkMatchOperator_Regex_SQLInjection benchmarks regex matching against a
// realistic OWASP-style SQL injection pattern with a long input string.
func BenchmarkMatchOperator_Regex_SQLInjection(b *testing.B) {
	b.ReportAllocs()

	// Realistic OWASP CRS SQL injection detection pattern
	pattern := `(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b.*\bwhere\b|\bdrop\b\s+\btable\b|\binsert\b\s+\binto\b|\bdelete\b\s+\bfrom\b|\bupdate\b.*\bset\b|\bexec\b|\bexecute\b|\bxp_)`
	value := "id=1 UNION ALL SELECT username,password FROM admin_users WHERE role='admin'--"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MatchOperator(value, pattern, "rx")
	}
}

// BenchmarkMatchOperator_Regex_NoMatch benchmarks regex matching when the input
// does not match, forcing the engine to scan the entire string.
func BenchmarkMatchOperator_Regex_NoMatch(b *testing.B) {
	b.ReportAllocs()

	pattern := `(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b.*\bwhere\b|\bdrop\b\s+\btable\b)`
	value := "The quick brown fox jumps over the lazy dog. This is a perfectly normal request with no malicious content whatsoever."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MatchOperator(value, pattern, "rx")
	}
}

// BenchmarkEvaluateRequest_SQLInjection benchmarks the full rule engine pipeline
// with a realistic SQL injection detection rule matching against a malicious request.
func BenchmarkEvaluateRequest_SQLInjection(b *testing.B) {
	b.ReportAllocs()

	rules := []WAFRule{
		{
			ID:      "sqli-001",
			Enabled: true,
			Phase:   2,
			Action:  "block",
			Variables: []WAFVariable{
				{Name: "ARGS"},
				{Name: "QUERY_STRING"},
			},
			Operator: "rx",
			Pattern:  `(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b\s+\btable\b|\binsert\b\s+\binto\b|\bdelete\b\s+\bfrom\b)`,
		},
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		b.Fatalf("Failed to create rule engine: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/search?q=1'+UNION+SELECT+username,password+FROM+users--", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.EvaluateRequest(ctx, req)
	}
}

// BenchmarkApplyTransformations_SingleLowercase benchmarks the most common
// single-transformation case.
func BenchmarkApplyTransformations_SingleLowercase(b *testing.B) {
	b.ReportAllocs()
	input := "SELECT * FROM Users WHERE Id=1"
	transformations := []string{"lowercase"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ApplyTransformations(input, transformations)
	}
}

// BenchmarkApplyTransformations_URLDecode benchmarks URL decoding transformation.
func BenchmarkApplyTransformations_URLDecode(b *testing.B) {
	b.ReportAllocs()
	input := "%53%45%4C%45%43%54%20%2A%20%46%52%4F%4D%20%75%73%65%72%73"
	transformations := []string{"urlDecode"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ApplyTransformations(input, transformations)
	}
}

// BenchmarkApplyTransformations_FullChain benchmarks applying a full chain of
// transformations that a WAF rule might use for evasion detection.
func BenchmarkApplyTransformations_FullChain(b *testing.B) {
	b.ReportAllocs()
	input := "%53ELECT+%2A+%46ROM+%75sers%20WHERE%20id%3D1"
	transformations := []string{"lowercase", "urlDecode", "htmlEntityDecode", "removeComments", "compressWhitespace", "trim"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ApplyTransformations(input, transformations)
	}
}
