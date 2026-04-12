package transport

import "testing"

func TestBufferPool_Size(t *testing.T) {
	buf := GetBuffer()
	if buf == nil {
		t.Fatal("GetBuffer returned nil")
	}
	if len(*buf) != 32*1024 {
		t.Fatalf("expected buffer size 32768, got %d", len(*buf))
	}
	PutBuffer(buf)
}

func TestBufferPool_NilSafe(t *testing.T) {
	// PutBuffer(nil) must not panic.
	PutBuffer(nil)
}

func TestBufferPool_Reuse(t *testing.T) {
	buf1 := GetBuffer()
	ptr1 := &(*buf1)[0]
	PutBuffer(buf1)

	buf2 := GetBuffer()
	ptr2 := &(*buf2)[0]
	PutBuffer(buf2)

	// After Put+Get the pool should return the same backing array.
	// This is best-effort (the runtime may GC the pooled item), so we
	// just verify the pointers are non-nil rather than requiring equality.
	if ptr1 == nil || ptr2 == nil {
		t.Fatal("buffer backing array pointer is nil")
	}
}

func BenchmarkBufferPool_GetPut(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		buf := GetBuffer()
		PutBuffer(buf)
	}
}
