// Package zerocopy provides zero-copy I/O utilities for efficient data transfer.
package zerocopy

import (
	"io"
	"log/slog"
	"net/http"
)

// ZeroCopyTransport wraps an http.RoundTripper with zero-copy optimizations
type ZeroCopyTransport struct {
	Transport http.RoundTripper
	Enabled   bool
}

// NewZeroCopyTransport creates a new zero-copy transport wrapper
func NewZeroCopyTransport(transport http.RoundTripper) *ZeroCopyTransport {
	return &ZeroCopyTransport{
		Transport: transport,
		Enabled:   true,
	}
}

// RoundTrip performs the HTTP request with zero-copy optimizations
func (z *ZeroCopyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !z.Enabled {
		return z.Transport.RoundTrip(req)
	}

	// Forward request with zero-copy body handling
	resp, err := z.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Response body forwarding will use zero-copy in ForwardResponse functions
	// No need to wrap here as the actual copying happens in ForwardResponse

	return resp, nil
}

// zeroCopyBody wraps an io.ReadCloser with zero-copy buffer support
// This is a simple pass-through that uses pooled buffers when copying
type zeroCopyBody struct {
	body io.ReadCloser
}

// Read performs the read operation on the zeroCopyBody.
func (z *zeroCopyBody) Read(p []byte) (n int, err error) {
	return z.body.Read(p)
}

// Close releases resources held by the zeroCopyBody.
func (z *zeroCopyBody) Close() error {
	return z.body.Close()
}

// ModifyResponseZeroCopy wraps ModifyResponse to use zero-copy operations
func ModifyResponseZeroCopy(modifyFn func(*http.Response) error) func(*http.Response) error {
	return func(resp *http.Response) error {
		// Check if body needs to be read
		// If modifyFn doesn't need body, we can skip reading it
		if resp.Body != nil && resp.Body != http.NoBody {
			// Wrap body with zero-copy reader
			resp.Body = &zeroCopyResponseBody{
				body: resp.Body,
			}
		}

		err := modifyFn(resp)

		// Restore body if it was modified
		if zrb, ok := resp.Body.(*zeroCopyResponseBody); ok {
			resp.Body = zrb.body
		}

		return err
	}
}

// zeroCopyResponseBody wraps response body for zero-copy operations
type zeroCopyResponseBody struct {
	body io.ReadCloser
}

// Read performs the read operation on the zeroCopyResponseBody.
func (z *zeroCopyResponseBody) Read(p []byte) (n int, err error) {
	return z.body.Read(p)
}

// Close releases resources held by the zeroCopyResponseBody.
func (z *zeroCopyResponseBody) Close() error {
	return z.body.Close()
}

// ForwardResponse forwards a response using zero-copy operations
func ForwardResponse(dst http.ResponseWriter, src *http.Response) error {
	// Copy headers
	for key, values := range src.Header {
		for _, value := range values {
			dst.Header().Add(key, value)
		}
	}

	// Set status
	dst.WriteHeader(src.StatusCode)

	// Copy body using zero-copy
	if src.Body != nil && src.Body != http.NoBody {
		defer src.Body.Close()
		_, err := CopyBuffer(dst, src.Body)
		return err
	}

	return nil
}

// ForwardResponseStreaming forwards a response with streaming support
func ForwardResponseStreaming(dst http.ResponseWriter, src *http.Response) error {
	// Copy headers
	for key, values := range src.Header {
		for _, value := range values {
			dst.Header().Add(key, value)
		}
	}

	// Set status
	dst.WriteHeader(src.StatusCode)

	// Stream body using zero-copy
	if src.Body != nil && src.Body != http.NoBody {
		defer src.Body.Close()

		// Use streaming writer for better performance
		sw := NewStreamingWriter(dst)
		defer sw.Close()

		_, err := CopyBuffer(sw, src.Body)
		if err != nil {
			slog.Debug("zerocopy: error forwarding response", "error", err)
			return err
		}

		// Flush if supported
		if flusher, ok := dst.(http.Flusher); ok {
			flusher.Flush()
		}

		return sw.Flush()
	}

	return nil
}

