package transport

import (
	"io"
	"strings"
	"testing"
)

func BenchmarkBufferPool_CopyBody(b *testing.B) {
	body := strings.Repeat("x", 8192)
	src := strings.NewReader(body)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := GetBuffer()
		src.Reset(body)
		io.CopyBuffer(io.Discard, src, *buf)
		PutBuffer(buf)
	}
}
