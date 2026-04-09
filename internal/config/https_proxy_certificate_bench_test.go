package config

import "testing"

func BenchmarkMITMCertificateGeneration(b *testing.B) {
	caCert, err := createTestCertificate("Benchmark CA", true)
	if err != nil {
		b.Fatalf("failed to create CA cert: %v", err)
	}
	gen, err := NewMITMCertificateGenerator(caCert)
	if err != nil {
		b.Fatalf("failed to create generator: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := gen.GenerateCertificate("bench.example.com"); err != nil {
			b.Fatalf("GenerateCertificate failed: %v", err)
		}
	}
}

func BenchmarkMITMCertificateCacheHit(b *testing.B) {
	cache := NewCertificateCache(0)
	cache.Set("bench.example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Get("bench.example.com")
	}
}

