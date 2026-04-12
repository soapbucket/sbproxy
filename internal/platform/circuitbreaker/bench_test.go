package circuitbreaker

import (
	"testing"
	"time"
)

// BenchmarkCircuitBreakerCall measures the cost of a single Call through a
// closed circuit breaker (happy path).
func BenchmarkCircuitBreakerCall(b *testing.B) {
	cb := New(Config{
		Name:             "bench",
		FailureThreshold: 1000000,
		SuccessThreshold: 1,
		Timeout:          time.Second,
	})

	fn := func() error { return nil }

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.Call(fn)
	}
}

// BenchmarkCircuitBreakerConcurrent measures concurrent throughput of
// Call on a closed circuit breaker.
func BenchmarkCircuitBreakerConcurrent(b *testing.B) {
	cb := New(Config{
		Name:             "bench-parallel",
		FailureThreshold: 1000000,
		SuccessThreshold: 1,
		Timeout:          time.Second,
	})

	fn := func() error { return nil }

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cb.Call(fn)
		}
	})
}

// BenchmarkCircuitBreakerCall_Open measures the cost of a Call when the
// circuit is open (fast-reject path).
func BenchmarkCircuitBreakerCall_Open(b *testing.B) {
	cb := New(Config{
		Name:             "bench-open",
		FailureThreshold: 1,
		SuccessThreshold: 1,
		Timeout:          time.Hour, // stay open
	})

	// Trip the breaker
	_ = cb.Call(func() error { return errService })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.Call(func() error { return nil })
	}
}

// BenchmarkRegistryGetOrCreate measures the cost of registry lookups
// when the breaker already exists.
func BenchmarkRegistryGetOrCreate(b *testing.B) {
	reg := NewRegistry()
	reg.GetOrCreate("existing", DefaultConfig)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.GetOrCreate("existing", DefaultConfig)
	}
}

// BenchmarkRegistryGetOrCreate_Concurrent measures concurrent registry lookups.
func BenchmarkRegistryGetOrCreate_Concurrent(b *testing.B) {
	reg := NewRegistry()
	reg.GetOrCreate("existing", DefaultConfig)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reg.GetOrCreate("existing", DefaultConfig)
		}
	})
}
