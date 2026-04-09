package policy

import (
	"fmt"
	"testing"
)

func BenchmarkTPMCheck(b *testing.B) {
	tpm := NewTPMLimiter()
	tpm.Record("bench-user", 500)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tpm.Check("bench-user", 100, 10000)
	}
}

func BenchmarkTPMRecord(b *testing.B) {
	tpm := NewTPMLimiter()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tpm.Record("bench-user", 10)
	}
}

func BenchmarkTPMParallel(b *testing.B) {
	tpm := NewTPMLimiter()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("user-%d", i%100)
			tpm.Record(key, 10)
			tpm.Check(key, 10, 100000)
			i++
		}
	})
}
