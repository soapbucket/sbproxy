// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

var _ http.ResponseWriter = (*SavedResponseWriter)(nil)

// Pool for SavedResponseWriter to reduce allocations
var savedResponseWriterPool = sync.Pool{
	New: func() interface{} {
		return &SavedResponseWriter{
			header: make(http.Header),
			body:   &bytes.Buffer{},
			status: http.StatusOK,
		}
	},
}

// SavedResponseWriter represents a saved response writer.
type SavedResponseWriter struct {
	header http.Header
	body   *bytes.Buffer
	status int
}

// Header performs the header operation on the SavedResponseWriter.
func (r *SavedResponseWriter) Header() http.Header {
	return r.header
}

// WriteHeader performs the write header operation on the SavedResponseWriter.
func (r *SavedResponseWriter) WriteHeader(status int) {
	r.status = status
}

// Write performs the write operation on the SavedResponseWriter.
func (r *SavedResponseWriter) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

// GetBody returns the body for the SavedResponseWriter.
func (r *SavedResponseWriter) GetBody() io.ReadCloser {
	return io.NopCloser(r.body)
}

// GetHeader returns the header for the SavedResponseWriter.
func (r *SavedResponseWriter) GetHeader() http.Header {
	return r.header
}

// GetStatus returns the status for the SavedResponseWriter.
func (r *SavedResponseWriter) GetStatus() int {
	return r.status
}

// NewSavedResponseWriter creates and initializes a new SavedResponseWriter.
func NewSavedResponseWriter() *SavedResponseWriter {
	srw := savedResponseWriterPool.Get().(*SavedResponseWriter)
	// Reset the writer
	for k := range srw.header {
		delete(srw.header, k)
	}
	srw.body.Reset()
	srw.status = http.StatusOK
	return srw
}

// ReleaseSavedResponseWriter returns the writer to the pool
func ReleaseSavedResponseWriter(srw *SavedResponseWriter) {
	// Clear to help GC
	for k := range srw.header {
		delete(srw.header, k)
	}
	srw.body.Reset()
	savedResponseWriterPool.Put(srw)
}
