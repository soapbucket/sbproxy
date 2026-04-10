package waf

import "testing"

func BenchmarkAutoUpdater_ParseJSONRules_Wrapped(b *testing.B) {
	b.ReportAllocs()
	au := &AutoUpdater{}
	data := []byte(`{"rules":[` +
		`{"id":"100001","name":"test-rule-1","enabled":true,"severity":"critical","operator":"rx","pattern":"select.*from"},` +
		`{"id":"100002","name":"test-rule-2","enabled":true,"severity":"warning","operator":"rx","pattern":"union.*select"},` +
		`{"id":"100003","name":"test-rule-3","enabled":true,"severity":"notice","operator":"rx","pattern":"drop\\s+table"}` +
		`]}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		au.parseJSONRules(data)
	}
}

func BenchmarkAutoUpdater_ParseJSONRules_Array(b *testing.B) {
	b.ReportAllocs()
	au := &AutoUpdater{}
	data := []byte(`[` +
		`{"id":"100001","name":"test-rule-1","enabled":true,"severity":"critical","operator":"rx","pattern":"select.*from"},` +
		`{"id":"100002","name":"test-rule-2","enabled":true,"severity":"warning","operator":"rx","pattern":"union.*select"}` +
		`]`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		au.parseJSONRules(data)
	}
}

func BenchmarkAutoUpdater_Rules(b *testing.B) {
	b.ReportAllocs()
	au := NewAutoUpdater(AutoUpdateConfig{Enabled: true, MaxRules: 1000}, nil)
	au.mu.Lock()
	for i := 0; i < 100; i++ {
		au.rules = append(au.rules, WAFRule{
			ID:       "rule-" + string(rune('0'+i%10)),
			Name:     "test-rule",
			Enabled:  true,
			Severity: "warning",
		})
	}
	au.mu.Unlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		au.Rules()
	}
}
