package pii

import (
	"testing"
)

func BenchmarkScanWhole(b *testing.B) {
	body := generateTestBody(50*1024, true)
	scanner := NewScanner(DefaultDetectors(), nil, 0)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(body, "/test")
	}
}

func BenchmarkScanPieces(b *testing.B) {
	body := generateTestBody(50*1024, true)
	// Split into 100 pieces
	pieceSize := len(body) / 100
	scanner := NewScanner(DefaultDetectors(), nil, 0)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			start := j * pieceSize
			end := (j + 1) * pieceSize
			if j == 99 {
				end = len(body)
			}
			scanner.Scan(body[start:end], "/test")
		}
	}
}
