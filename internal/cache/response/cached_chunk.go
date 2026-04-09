// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"bytes"
	"context"
	"encoding/gob"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// buildChunkKey builds a cache key for chunked responses using a pooled string builder.
func buildChunkKey(URL *url.URL) string {
	sorted := httputil.SortURLParams(URL).String()
	b := cacher.GetBuilderWithSize(6 + len(sorted))
	b.WriteString("chunk:")
	b.WriteString(sorted)
	key := b.String()
	cacher.PutBuilder(b)
	return key
}

// CachedChunkedResponse represents the response from a cached chunked operation.
type CachedChunkedResponse struct {
	Headers http.Header
	Body    []byte
}

// CachedChunkedResponseWriter represents a cached chunked response writer.
type CachedChunkedResponseWriter struct {
	headers        http.Header
	writtenHeaders http.Header
	rw             http.ResponseWriter
	offset         int
	status         int
	flusher        http.Flusher
	protocol       string // Store protocol version for proper handling
}

// Header performs the header operation on the CachedChunkedResponseWriter.
func (c *CachedChunkedResponseWriter) Header() http.Header {
	return c.headers
}

// WriteHeader performs the write header operation on the CachedChunkedResponseWriter.
func (c *CachedChunkedResponseWriter) WriteHeader(status int) {
	c.status = status

	// remove any written headers
	for key := range c.writtenHeaders {
		delete(c.headers, key)
	}

	// remove the content length
	c.headers.Del("Content-Length")

	// Don't convert to trailers for HTTP/3 - it handles framing natively via QUIC
	// Only convert headers to trailers for HTTP/1.1 and HTTP/2
	if c.protocol != "HTTP/3.0" && c.protocol != "HTTP/3" {
		// convert the keys to trailers
		keys := make([]string, 0, len(c.headers))
		for key := range c.headers {
			keys = append(keys, key)
		}
		for _, key := range keys {
			c.headers[http.TrailerPrefix+key] = c.headers[key]
			delete(c.headers, key)
		}
	}
}

// Write performs the write operation on the CachedChunkedResponseWriter.
func (c *CachedChunkedResponseWriter) Write(p []byte) (n int, err error) {
	if c.status == 0 {
		c.WriteHeader(http.StatusOK)
	}

	n = len(p)

	switch {
	case c.offset > n:
		c.offset -= n

	case c.offset < n:
		index := n - c.offset
		c.offset = 0

		// if we run into an error, return bytes written
		if n2, err2 := c.rw.Write(p[index:]); err2 != nil {
			return n2 + index, err2
		}
	default:
		n, err = c.rw.Write(p)
	}

	return n, err
}

// Flush performs the flush operation on the CachedChunkedResponseWriter.
func (c *CachedChunkedResponseWriter) Flush() {
	if c.flusher != nil {
		c.flusher.Flush()
	}
}

// GetCachedChunkResponse returns the cached chunk response.
func GetCachedChunkResponse(store cacher.Cacher, URL *url.URL) (*CachedChunkedResponse, bool) {
	key := buildChunkKey(URL)
	hkey := crypto.GetHashFromString(key)

	slog.Debug("getting response", "key", key, "hkey", hkey)

	reader, err := store.Get(context.Background(), "chunk", hkey)
	if err != nil {
		slog.Debug("obj not found", "hkey", hkey)
		return nil, false
	}

	data, readErr := io.ReadAll(reader)
	if readErr != nil || len(data) == 0 {
		slog.Debug("obj not found or empty", "hkey", hkey)
		return nil, false
	}

	reader = bytes.NewReader(data)
	resp := new(CachedChunkedResponse)
	if err := gob.NewDecoder(reader).Decode(resp); err != nil {
		slog.Error("error unmarshalling obj", "error", err)
		return nil, false
	}
	return resp, true
}

// SaveCachedChunkResponse performs the save cached chunk response operation.
func SaveCachedChunkResponse(store cacher.Cacher, URL *url.URL, resp *CachedChunkedResponse, d time.Duration) error {
	key := buildChunkKey(URL)
	hkey := crypto.GetHashFromString(key)

	slog.Debug("saving response", "key", key, "hkey", hkey)

	writer := new(bytes.Buffer)
	if err := gob.NewEncoder(writer).Encode(resp); err != nil {
		slog.Error("error encoding cache", "hkey", hkey, "error", err)
		return err
	}

	if err := store.PutWithExpires(context.Background(), "chunk", hkey, bytes.NewReader(writer.Bytes()), d); err != nil {
		slog.Error("error storing response", "hkey", hkey, "error", err)
		return err
	}

	return nil
}
