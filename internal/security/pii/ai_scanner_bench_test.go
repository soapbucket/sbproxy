package pii

import "testing"

func BenchmarkAITrafficScanner_ScanRequest_WithPII(b *testing.B) {
	b.ReportAllocs()
	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      true,
		ScanRequests: true,
		Mode:         "warn",
	})
	body := []byte(`{"messages":[{"role":"user","content":"My email is test@example.com and my phone is 555-123-4567"}]}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanRequest(body, "gpt-4", "openai")
	}
}

func BenchmarkAITrafficScanner_ScanRequest_NoPII(b *testing.B) {
	b.ReportAllocs()
	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      true,
		ScanRequests: true,
		Mode:         "warn",
	})
	body := []byte(`{"messages":[{"role":"user","content":"What is the capital of France?"}]}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanRequest(body, "gpt-4", "openai")
	}
}

func BenchmarkAITrafficScanner_ScanRequest_Disabled(b *testing.B) {
	b.ReportAllocs()
	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      false,
		ScanRequests: true,
		Mode:         "warn",
	})
	body := []byte(`{"messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanRequest(body, "gpt-4", "openai")
	}
}

func BenchmarkAITrafficScanner_ScanRequest_ExemptModel(b *testing.B) {
	b.ReportAllocs()
	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      true,
		ScanRequests: true,
		Mode:         "warn",
		ExemptModels: []string{"gpt-4"},
	})
	body := []byte(`{"messages":[{"role":"user","content":"My email is test@example.com"}]}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanRequest(body, "gpt-4", "openai")
	}
}
