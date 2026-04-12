// Package zerocopy provides zero-copy I/O utilities for efficient data transfer.
package zerocopy

import (
	"io"
	"net/http"
)

// OptimizeRequest optimizes a request for zero-copy operations
// Returns a function to restore the original body if needed
func OptimizeRequest(req *http.Request) (restore func()) {
	if req.Body == nil || req.Body == http.NoBody {
		return func() {}
	}

	// If GetBody is already set, we're good
	if req.GetBody != nil {
		return func() {}
	}

	// Do not set a broken GetBody here. The original body is a single-use
	// stream and cannot be returned multiple times. Callers that need retry
	// support should use MakeRequestRetryable, which properly buffers the body.
	return func() {}
}

// OptimizeResponse optimizes a response for zero-copy forwarding
func OptimizeResponse(resp *http.Response) {
	// Ensure Content-Length is set if known (helps with zero-copy)
	if resp.ContentLength < 0 && resp.Body != nil {
		// Try to determine size from headers
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			// Content-Length will be set by http library
			_ = cl
		}
	}
}

// ShouldUseZeroCopy determines if zero-copy should be used based on response size
func ShouldUseZeroCopy(resp *http.Response, threshold int64) bool {
	if resp == nil {
		return false
	}

	// Use zero-copy for large responses
	if resp.ContentLength > threshold {
		return true
	}

	// Use zero-copy for streaming responses (chunked)
	if len(resp.TransferEncoding) > 0 {
		return true
	}

	// Use zero-copy for responses without Content-Length (streaming)
	if resp.ContentLength < 0 {
		return true
	}

	return false
}

// CopyWithZeroCopy copies data using zero-copy optimizations
// Returns the number of bytes written and any error
func CopyWithZeroCopy(dst io.Writer, src io.Reader, size int64) (written int64, err error) {
	// Choose buffer size based on data size
	if size > 0 && size < DefaultBufferSize {
		// Small data, use small buffer
		buf := GetSmallBuffer()
		defer PutSmallBuffer(buf)
		return io.CopyBuffer(dst, src, buf)
	} else if size > 0 && size > LargeBufferSize {
		// Very large data, use large buffer
		buf := GetLargeBuffer()
		defer PutLargeBuffer(buf)
		return io.CopyBuffer(dst, src, buf)
	}

	// Default buffer
	return CopyBuffer(dst, src)
}

// ReadBodyZeroCopy reads a request/response body using zero-copy
// Only reads if necessary (e.g., for modifications)
func ReadBodyZeroCopy(body io.ReadCloser, maxSize int64) ([]byte, error) {
	if body == nil || body == http.NoBody {
		return nil, nil
	}
	defer body.Close()

	if maxSize > 0 {
		return ReadAllPooledWithLimit(body, maxSize)
	}

	return ReadAllPooled(body)
}
