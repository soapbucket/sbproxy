// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"log/slog"
	"net/http"
)

// ChunkContinuationWriter is a response writer that continues writing after a cached chunk
// It doesn't try to write headers (they've already been sent) and tracks the offset
type ChunkContinuationWriter struct {
	rw              http.ResponseWriter
	offset          int // Bytes already written (cached chunk size)
	flusher         http.Flusher
	headersWritten  bool
	bytesWritten    int
}

// Header performs the header operation on the ChunkContinuationWriter.
func (c *ChunkContinuationWriter) Header() http.Header {
	// Headers already sent, return empty map to prevent modifications
	return make(http.Header)
}

// WriteHeader performs the write header operation on the ChunkContinuationWriter.
func (c *ChunkContinuationWriter) WriteHeader(status int) {
	// Headers already sent with cached chunk - ignore this call
	// Log if it's not 200 OK (indicates potential issue)
	if status != http.StatusOK && !c.headersWritten {
		slog.Warn("chunk continuation: upstream returned non-200 status after cached chunk sent",
			"status", status,
			"note", "headers already sent, cannot change status")
	}
	c.headersWritten = true
}

// Write performs the write operation on the ChunkContinuationWriter.
func (c *ChunkContinuationWriter) Write(p []byte) (n int, err error) {
	// Ensure WriteHeader was called (even if we ignore it)
	if !c.headersWritten {
		c.WriteHeader(http.StatusOK)
	}

	n = len(p)

	// Skip bytes that were already sent in cached chunk
	switch {
	case c.offset > n:
		// Entire chunk was already sent, just reduce offset
		c.offset -= n
		slog.Debug("chunk continuation: skipping bytes already sent", 
			"bytes_to_skip", n, 
			"offset_remaining", c.offset)
		
	case c.offset > 0:
		// Partial overlap: skip the offset bytes, write the rest
		index := c.offset
		c.offset = 0
		
		slog.Debug("chunk continuation: partial overlap", 
			"skipping", index, 
			"writing", n-index)
		
		// Write only the new bytes
		if index < n {
			n2, err2 := c.rw.Write(p[index:])
			if err2 != nil {
				return index + n2, err2
			}
			c.bytesWritten += n2
		}
		
	default:
		// No overlap, write everything
		n, err = c.rw.Write(p)
		c.bytesWritten += n
	}

	return n, err
}

// Flush performs the flush operation on the ChunkContinuationWriter.
func (c *ChunkContinuationWriter) Flush() {
	if c.flusher != nil {
		c.flusher.Flush()
	}
}

// Unwrap returns the underlying response writer
func (c *ChunkContinuationWriter) Unwrap() http.ResponseWriter {
	return c.rw
}

