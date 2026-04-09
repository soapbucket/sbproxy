package config

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// BenchmarkBufferPool tests the performance of the buffer pool
func BenchmarkBufferPool(b *testing.B) {
	b.ReportAllocs()
	b.Run("with_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := getBuffer()
			*buf = append(*buf, []byte("test data for buffer pool")...)
			putBuffer(buf)
		}
	})

	b.Run("without_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 0, 64*1024)
			buf = append(buf, []byte("test data for buffer pool")...)
			_ = buf
		}
	})
}

// BenchmarkBufferPool_NormalSize benchmarks get/put of 4KB buffers to verify
// no regression from the oversized discard check in putBuffer.
func BenchmarkBufferPool_NormalSize(b *testing.B) {
	InitBufferPools()
	defer ShutdownBufferPools()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := getSmallBuffer() // 4KB
		*buf = append(*buf, make([]byte, 4096)...)
		putSmallBuffer(buf)
	}
}

// BenchmarkSmallBufferPool tests the performance of the small buffer pool
func BenchmarkSmallBufferPool(b *testing.B) {
	b.ReportAllocs()
	b.Run("with_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := getSmallBuffer()
			*buf = append(*buf, []byte("small data")...)
			putSmallBuffer(buf)
		}
	})

	b.Run("without_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 0, 4*1024)
			buf = append(buf, []byte("small data")...)
			_ = buf
		}
	})
}

// BenchmarkBytesBufferPool tests the performance of the bytes.Buffer pool
func BenchmarkBytesBufferPool(b *testing.B) {
	b.ReportAllocs()
	b.Run("with_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := getBytesBuffer()
			buf.WriteString("test string for bytes buffer")
			putBytesBuffer(buf)
		}
	})

	b.Run("without_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := new(bytes.Buffer)
			buf.WriteString("test string for bytes buffer")
			_ = buf
		}
	})
}

// BenchmarkStringSlicePool tests the performance of the string slice pool
func BenchmarkStringSlicePool(b *testing.B) {
	b.ReportAllocs()
	b.Run("with_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			slice := getStringSlice()
			*slice = append(*slice, "key1", "key2", "key3")
			putStringSlice(slice)
		}
	})

	b.Run("without_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			slice := make([]string, 0, 10)
			slice = append(slice, "key1", "key2", "key3")
			_ = slice
		}
	})
}

// BenchmarkMapPool tests the performance of the map pool
func BenchmarkMapPool(b *testing.B) {
	b.ReportAllocs()
	b.Run("with_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m := getMap()
			m["key1"] = "value1"
			m["key2"] = "value2"
			m["key3"] = "value3"
			putMap(m)
		}
	})

	b.Run("without_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m := make(map[string]interface{}, 16)
			m["key1"] = "value1"
			m["key2"] = "value2"
			m["key3"] = "value3"
			_ = m
		}
	})
}

// BenchmarkRegexCache tests the performance of regex caching
func BenchmarkRegexCache(b *testing.B) {
	b.ReportAllocs()
	patterns := []string{
		`\d+`,
		`[a-z]+`,
		`\w+@\w+\.\w+`,
		`https?://[^\s]+`,
		`\b[A-Z][a-z]*\b`,
	}

	b.Run("with_cache", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			pattern := patterns[i%len(patterns)]
			_, _ = getCompiledRegex(pattern)
		}
	})

	b.Run("without_cache", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			pattern := patterns[i%len(patterns)]
			// Simulate compilation without caching
			_, _ = getCompiledRegex(pattern)
		}
	})
}

// BenchmarkEchoActionWithPools tests the full echo action with pool optimizations
func BenchmarkEchoActionWithPools(b *testing.B) {
	b.ReportAllocs()
	cfg := &EchoActionConfig{
		EchoConfig: EchoConfig{
			IncludeContext: false,
		},
	}
	transportFn := EchoTransportFn(cfg)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := mustCreateTestRequest("POST", "http://example.com/test", "test body content", b)
		_, _ = transportFn(req)
	}
}

// Helper function to create test requests for benchmarks
func mustCreateTestRequest(method, url, body string, b *testing.B) *http.Request {
	b.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		b.Fatalf("failed to create request: %v", err)
	}
	return req
}

