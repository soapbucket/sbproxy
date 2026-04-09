package pii

import (
	"bytes"
	"testing"
)

func hasPIICandidateBytesTable(data []byte) bool {
	for _, b := range data {
		if piiCandidateTable[b] {
			return true
		}
	}
	return false
}

func hasPIICandidateBytesLoop(data []byte) bool {
	for _, b := range data {
		if b == '@' || b == '-' || (b >= '0' && b <= '9') || b == '.' {
			return true
		}
	}
	return false
}

func hasPIICandidateBytesContainsAny(data []byte) bool {
	return bytes.ContainsAny(data, "0123456789@-.")
}

func BenchmarkCandidateLoop(b *testing.B) {
	body := make([]byte, 50*1024)
	for i := range body {
		body[i] = 'a'
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasPIICandidateBytesLoop(body)
	}
}

func BenchmarkCandidateTable(b *testing.B) {
	body := make([]byte, 50*1024)
	for i := range body {
		body[i] = 'a'
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasPIICandidateBytesTable(body)
	}
}

func BenchmarkCandidateContainsAny(b *testing.B) {
	body := make([]byte, 50*1024)
	for i := range body {
		body[i] = 'a'
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasPIICandidateBytesContainsAny(body)
	}
}
