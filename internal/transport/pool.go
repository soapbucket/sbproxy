// pool.go provides a sync.Pool for reusable body copy buffers.
package transport

import "sync"

// bodyBufferPool uses pointer-to-slice (*[]byte) to avoid interface boxing
// allocations on every Get/Put cycle. This is the Caddy pattern for high-throughput
// buffer reuse in hot proxy paths.
var bodyBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// GetBuffer returns a *[]byte from the pool. The returned buffer is 32 KiB.
// Callers must call PutBuffer when finished.
func GetBuffer() *[]byte {
	return bodyBufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool. Nil pointers are safely ignored.
func PutBuffer(buf *[]byte) {
	if buf == nil {
		return
	}
	bodyBufferPool.Put(buf)
}
