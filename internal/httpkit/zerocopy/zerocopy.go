// Package zerocopy provides zero-copy I/O utilities for efficient data transfer.
package zerocopy

import (
	"io"

	"github.com/soapbucket/sbproxy/internal/httpkit/bufferpool"
)

const (
	// DefaultBufferSize is the default size for zero-copy buffers (64KB)
	DefaultBufferSize = 64 * 1024
	
	// LargeBufferSize is for large responses (256KB)
	LargeBufferSize = 256 * 1024
	
	// SmallBufferSize is for small operations (4KB)
	SmallBufferSize = 4 * 1024
)

var (
	// Adaptive buffer pool (shared with internal/config)
	// Initialized via InitBufferPools during startup
	adaptivePool *bufferpool.AdaptiveBufferPool
)

// InitBufferPools initializes the adaptive buffer pool for zerocopy operations
// This should be called once during application startup
func InitBufferPools(pool *bufferpool.AdaptiveBufferPool) {
	adaptivePool = pool
}

// GetBuffer gets a buffer from the adaptive pool
// The caller must call PutBuffer when done
func GetBuffer() []byte {
	if adaptivePool != nil {
		buf := adaptivePool.Get(DefaultBufferSize)
		return *buf
	}
	// Fallback to direct allocation
	return make([]byte, DefaultBufferSize)
}

// PutBuffer returns a buffer to the adaptive pool
func PutBuffer(buf []byte) {
	if buf != nil && adaptivePool != nil {
		// AdaptiveBufferPool.Put() handles buffer clearing for security
		adaptivePool.Put(&buf)
	}
}

// GetLargeBuffer gets a large buffer from the adaptive pool
func GetLargeBuffer() []byte {
	if adaptivePool != nil {
		buf := adaptivePool.Get(LargeBufferSize)
		return *buf
	}
	// Fallback
	return make([]byte, LargeBufferSize)
}

// PutLargeBuffer returns a large buffer to the adaptive pool
func PutLargeBuffer(buf []byte) {
	if buf != nil && adaptivePool != nil {
		// AdaptiveBufferPool.Put() handles buffer clearing for security
		adaptivePool.Put(&buf)
	}
}

// GetSmallBuffer gets a small buffer from the adaptive pool
func GetSmallBuffer() []byte {
	if adaptivePool != nil {
		buf := adaptivePool.Get(SmallBufferSize)
		return *buf
	}
	// Fallback
	return make([]byte, SmallBufferSize)
}

// PutSmallBuffer returns a small buffer to the adaptive pool
func PutSmallBuffer(buf []byte) {
	if buf != nil && adaptivePool != nil {
		// AdaptiveBufferPool.Put() handles buffer clearing for security
		adaptivePool.Put(&buf)
	}
}

// CopyBuffer performs zero-copy buffer operations using pooled buffers
// This is optimized for copying between readers and writers
func CopyBuffer(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := GetBuffer()
	defer PutBuffer(buf)
	return io.CopyBuffer(dst, src, buf)
}

// CopyBufferLarge uses a large buffer for copying large streams
func CopyBufferLarge(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := GetLargeBuffer()
	defer PutBuffer(buf)
	return io.CopyBuffer(dst, src, buf)
}

// BufferList is a collection of pooled buffers
type BufferList struct {
	buffers [][]byte
}

// Release returns all buffers in the list to the pool
func (bl *BufferList) Release() {
	for _, b := range bl.buffers {
		PutBuffer(b)
	}
	bl.buffers = nil
}

// Bytes returns a single byte slice by copying all buffers
// Note: This involves a copy, so use carefully.
func (bl *BufferList) Bytes() []byte {
	var total int
	for _, b := range bl.buffers {
		total += len(b)
	}
	res := make([]byte, total)
	var offset int
	for _, b := range bl.buffers {
		copy(res[offset:], b)
		offset += len(b)
	}
	return res
}

// Len returns the total length of data in the buffer list
func (bl *BufferList) Len() int {
	var total int
	for _, b := range bl.buffers {
		total += len(b)
	}
	return total
}

// WriteTo writes the contents of the buffer list to w
func (bl *BufferList) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for _, b := range bl.buffers {
		n, err := w.Write(b)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ReadAllToBufferList reads all data from r into a BufferList using pooled buffers
func ReadAllToBufferList(r io.Reader) (*BufferList, error) {
	if r == nil {
		return &BufferList{}, nil
	}

	bl := &BufferList{
		buffers: make([][]byte, 0, 4),
	}

	for {
		buf := GetBuffer()
		n, err := r.Read(buf)
		if n > 0 {
			bl.buffers = append(bl.buffers, buf[:n])
		} else {
			PutBuffer(buf)
		}
		
		if err == io.EOF {
			break
		}
		if err != nil {
			bl.Release()
			return nil, err
		}
	}

	return bl, nil
}

// ReadAllPooled reads all data from r using a pooled buffer
// This avoids allocating a new buffer for each read operation
func ReadAllPooled(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}

	buf := GetBuffer()
	defer PutBuffer(buf)

	var result []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// ReadAllPooledWithLimit reads data up to a limit using pooled buffers
// Returns error if limit is exceeded
func ReadAllPooledWithLimit(r io.Reader, limit int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}

	buf := GetBuffer()
	defer PutBuffer(buf)

	var result []byte
	var total int64

	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return nil, io.ErrUnexpectedEOF
			}
			result = append(result, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// StreamingWriter wraps an io.Writer with zero-copy streaming capabilities
type StreamingWriter struct {
	w   io.Writer
	buf []byte
}

// NewStreamingWriter creates a new streaming writer with pooled buffer
func NewStreamingWriter(w io.Writer) *StreamingWriter {
	return &StreamingWriter{
		w:   w,
		buf: GetBuffer(),
	}
}

// Write writes data using the pooled buffer
func (sw *StreamingWriter) Write(p []byte) (n int, err error) {
	// For small writes, use the buffer directly
	if len(p) <= len(sw.buf) {
		return sw.w.Write(p)
	}

	// For large writes, write directly and use buffer for chunking
	written := 0
	for written < len(p) {
		chunkSize := len(sw.buf)
		if remaining := len(p) - written; remaining < chunkSize {
			chunkSize = remaining
		}
		copy(sw.buf, p[written:written+chunkSize])
		n, err := sw.w.Write(sw.buf[:chunkSize])
		written += n
		if err != nil {
			return written, err
		}
	}

	return written, nil
}

// Close releases the buffer back to the pool
func (sw *StreamingWriter) Close() error {
	if sw.buf != nil {
		PutBuffer(sw.buf)
		sw.buf = nil
	}
	return nil
}

// Flush flushes the underlying writer if it supports flushing
func (sw *StreamingWriter) Flush() error {
	if flusher, ok := sw.w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// TeeReader creates a reader that writes to multiple writers using zero-copy
type TeeReader struct {
	r io.Reader
	w io.Writer
}

// NewTeeReader creates a new tee reader
func NewTeeReader(r io.Reader, w io.Writer) *TeeReader {
	return &TeeReader{r: r, w: w}
}

// Read reads from the reader and writes to the writer using pooled buffers
func (tr *TeeReader) Read(p []byte) (n int, err error) {
	n, err = tr.r.Read(p)
	if n > 0 {
		// Use pooled buffer for writing
		buf := GetBuffer()
		copy(buf, p[:n])
		_, writeErr := tr.w.Write(buf[:n])
		PutBuffer(buf)
		if writeErr != nil && err == nil {
			err = writeErr
		}
	}
	return n, err
}

// MultiWriter creates a writer that writes to multiple writers using zero-copy
type MultiWriter struct {
	writers []io.Writer
	buf     []byte
}

// NewMultiWriter creates a new multi-writer with pooled buffer
func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{
		writers: writers,
		buf:     GetBuffer(),
	}
}

// Write writes to all writers using pooled buffer
func (mw *MultiWriter) Write(p []byte) (n int, err error) {
	if len(p) <= len(mw.buf) {
		// Small write, use buffer
		copy(mw.buf, p)
		for _, w := range mw.writers {
			n, err := w.Write(mw.buf[:len(p)])
			if err != nil {
				return n, err
			}
		}
		return len(p), nil
	}

	// Large write, write directly
	for _, w := range mw.writers {
		n, err := w.Write(p)
		if err != nil {
			return n, err
		}
	}
	return len(p), nil
}

// Close releases the buffer
func (mw *MultiWriter) Close() error {
	if mw.buf != nil {
		PutBuffer(mw.buf)
		mw.buf = nil
	}
	return nil
}

// LimitedReader wraps an io.LimitedReader with zero-copy buffer support
type LimitedReader struct {
	R io.Reader
	N int64
}

// Read reads up to N bytes using pooled buffers
func (l *LimitedReader) Read(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
	}
	n, err = l.R.Read(p)
	l.N -= int64(n)
	return
}

// NewLimitedReader creates a new limited reader
func NewLimitedReader(r io.Reader, n int64) *LimitedReader {
	return &LimitedReader{R: r, N: n}
}

