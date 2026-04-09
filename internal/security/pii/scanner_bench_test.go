package pii

import (
	"fmt"
	"strings"
	"testing"
)

func generateTestBody(size int, withPII bool) []byte {
	base := `{"name":"John Doe","city":"New York","country":"US","active":true,"score":42}`
	if withPII {
		base = `{"name":"John Doe","ssn":"123-45-6789","email":"john@example.com","card":"4111111111111111","phone":"555-123-4567"}`
	}

	// Repeat to reach desired size
	repetitions := size / len(base)
	if repetitions < 1 {
		repetitions = 1
	}
	parts := make([]string, repetitions)
	for i := range parts {
		parts[i] = base
	}
	return []byte("[" + strings.Join(parts, ",") + "]")
}

func BenchmarkSSNDetector(b *testing.B) {
	d := NewSSNDetector()
	sizes := []int{1024, 5 * 1024, 50 * 1024}

	for _, size := range sizes {
		body := generateTestBody(size, true)
		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d.Detect(body, "")
			}
		})
	}
}

func BenchmarkCreditCardDetector(b *testing.B) {
	d := NewCreditCardDetector()
	sizes := []int{1024, 5 * 1024, 50 * 1024}

	for _, size := range sizes {
		body := generateTestBody(size, true)
		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d.Detect(body, "")
			}
		})
	}
}

func BenchmarkEmailDetector(b *testing.B) {
	d := NewEmailDetector()
	sizes := []int{1024, 5 * 1024, 50 * 1024}

	for _, size := range sizes {
		body := generateTestBody(size, true)
		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d.Detect(body, "")
			}
		})
	}
}

func BenchmarkScanner_AllDetectors(b *testing.B) {
	scanner := NewScanner(DefaultDetectors(), nil, 0)
	sizes := []int{1024, 5 * 1024, 50 * 1024, 500 * 1024}

	for _, size := range sizes {
		body := generateTestBody(size, true)
		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanner.Scan(body, "/test")
			}
		})
	}
}

func BenchmarkScanner_CleanBody(b *testing.B) {
	scanner := NewScanner(DefaultDetectors(), nil, 0)
	sizes := []int{1024, 5 * 1024, 50 * 1024}

	for _, size := range sizes {
		body := generateTestBody(size, false)
		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanner.Scan(body, "/test")
			}
		})
	}
}

func BenchmarkJSONScanner(b *testing.B) {
	scanner := NewScanner(DefaultDetectors(), nil, 0)
	js := NewJSONScanner(scanner)
	sizes := []int{1024, 5 * 1024, 50 * 1024}

	for _, size := range sizes {
		body := generateTestBody(size, true)
		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				js.ScanJSON(body, "/test")
			}
		})
	}
}

func BenchmarkJSONScanner_CleanBody(b *testing.B) {
	scanner := NewScanner(DefaultDetectors(), nil, 0)
	js := NewJSONScanner(scanner)
	sizes := []int{1024, 5 * 1024, 50 * 1024}

	for _, size := range sizes {
		body := generateTestBody(size, false)
		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				js.ScanJSON(body, "/test")
			}
		})
	}
}

func BenchmarkScanner_Parallel(b *testing.B) {
	scanner := NewScanner(DefaultDetectors(), nil, 0)
	body := generateTestBody(5*1024, true)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			scanner.Scan(body, "/test")
		}
	})
}

func BenchmarkLuhnCheck(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		luhnCheck("4111111111111111")
	}
}
