package zerocopy

import (
	"bytes"
	"github.com/soapbucket/sbproxy/internal/httpkit/bufferpool"
	"io"
	"testing"
)

func init() {
	pool := bufferpool.NewAdaptiveBufferPool(bufferpool.DefaultAdaptiveConfig())
	InitBufferPools(pool)
}

func BenchmarkReadAllPooled(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		_, err := ReadAllPooled(r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadAllToBufferList(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		bl, err := ReadAllToBufferList(r)
		if err != nil {
			b.Fatal(err)
		}
		bl.Release()
	}
}

func BenchmarkReadAllToBufferList_Large(b *testing.B) {
	data := make([]byte, 10*1024*1024) // 10MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		bl, err := ReadAllToBufferList(r)
		if err != nil {
			b.Fatal(err)
		}
		bl.Release()
	}
}

func BenchmarkReadAllStandard(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		_, err := io.ReadAll(r)
		if err != nil {
			b.Fatal(err)
		}
	}
}
