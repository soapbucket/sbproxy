// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"bytes"
	"context"
	"encoding/gob"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// MaxCachedResponseSize is the maximum allowed value for cached response size.
const MaxCachedResponseSize = 1024 * 1024

// Pool for gob encoding/decoding buffers
var gobBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Pool for CachedResponseWriter to reduce allocations
var cachedResponseWriterPool = sync.Pool{
	New: func() interface{} {
		return &CachedResponseWriter{}
	},
}

// CachedResponse represents the response from a cached operation.
type CachedResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
	Size    int
}

// IsTooLarge reports whether the CachedResponse is too large.
func (c *CachedResponse) IsTooLarge() bool {
	return len(c.Body) != c.Size
}

// CachedResponseWriter represents a cached response writer.
type CachedResponseWriter struct {
	rw       http.ResponseWriter
	buff     bytes.Buffer
	status   int
	capacity int
	size     int
}

// Header performs the header operation on the CachedResponseWriter.
func (c *CachedResponseWriter) Header() http.Header {
	return c.rw.Header()
}

// WriteHeader performs the write header operation on the CachedResponseWriter.
func (c *CachedResponseWriter) WriteHeader(status int) {
	c.status = status
	c.rw.WriteHeader(status)
}

// Write performs the write operation on the CachedResponseWriter.
func (c *CachedResponseWriter) Write(p []byte) (int, error) {
	if c.capacity == 0 || len(p)+c.size < c.capacity {
		c.buff.Write(p)
	}
	n, err := c.rw.Write(p)
	c.size += n
	return n, err
}

// Flush performs the flush operation on the CachedResponseWriter.
func (c *CachedResponseWriter) Flush() {
	if flusher, ok := c.rw.(http.Flusher); ok {
		flusher.Flush()
	}
}

// GetCachedResponse returns the cached response for the CachedResponseWriter.
func (c *CachedResponseWriter) GetCachedResponse() *CachedResponse {
	return &CachedResponse{
		Status:  c.status,
		Headers: c.rw.Header(),
		Body:    c.buff.Bytes(),
		Size:    c.size,
	}
}

// NewCachedResponseWriter creates and initializes a new CachedResponseWriter.
func NewCachedResponseWriter(rw http.ResponseWriter, capacity int) *CachedResponseWriter {
	crw := cachedResponseWriterPool.Get().(*CachedResponseWriter)
	crw.rw = rw
	crw.capacity = capacity
	crw.status = 0
	crw.size = 0
	crw.buff.Reset()
	return crw
}

// ReleaseCachedResponseWriter returns the writer to the pool
func ReleaseCachedResponseWriter(crw *CachedResponseWriter) {
	// Clear references to help GC
	crw.rw = nil
	crw.buff.Reset()
	cachedResponseWriterPool.Put(crw)
}

// GetCachedResponse returns the cached response.
func GetCachedResponse(store cacher.Cacher, URL *url.URL, ctx ...context.Context) (*CachedResponse, bool) {
	key := "cached:" + httputil.SortURLParams(URL).String()
	hkey := crypto.GetHashFromString(key)

	slog.Debug("getting response",
		logging.FieldCaller, "handler:GetCachedResponse",
		"key", key,
		"hkey", hkey)

	// Use provided context or fall back to a 5-second timeout
	var cacheCtx context.Context
	if len(ctx) > 0 && ctx[0] != nil {
		cacheCtx = ctx[0]
	} else {
		slog.Warn("GetCachedResponse called without context, using background context with 5s timeout",
			logging.FieldCaller, "handler:GetCachedResponse",
			"hkey", hkey)
		var cancel context.CancelFunc
		cacheCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}

	reader, err := store.Get(cacheCtx, "response", hkey)
	if err != nil {
		slog.Debug("obj not found",
			logging.FieldCaller, "handler:GetCachedResponse",
			"hkey", hkey)
		return nil, false
	}

	// Use pooled buffer to avoid double-copy (io.ReadAll + bytes.NewReader)
	buf := gobBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	_, readErr := buf.ReadFrom(reader)
	if readErr != nil || buf.Len() == 0 {
		buf.Reset()
		gobBufferPool.Put(buf)
		slog.Debug("obj not found or empty",
			logging.FieldCaller, "handler:GetCachedResponse",
			"hkey", hkey)
		return nil, false
	}

	resp := new(CachedResponse)
	if err = gob.NewDecoder(buf).Decode(resp); err != nil {
		buf.Reset()
		gobBufferPool.Put(buf)
		slog.Error("error unmarshalling obj",
			logging.FieldCaller, "handler:GetCachedResponse",
			logging.FieldError, err)
		return nil, false
	}
	buf.Reset()
	gobBufferPool.Put(buf)
	return resp, true
}

// SaveCachedResponse performs the save cached response operation.
func SaveCachedResponse(store cacher.Cacher, URL *url.URL, resp *CachedResponse, d time.Duration) error {
	key := "cached:" + httputil.SortURLParams(URL).String()
	hkey := crypto.GetHashFromString(key)

	slog.Debug("saving response",
		logging.FieldCaller, "handler:SaveCachedResponse",
		"key", key,
		"hkey", hkey)

	// Get buffer from pool
	writer := gobBufferPool.Get().(*bytes.Buffer)
	writer.Reset()
	defer func() {
		writer.Reset()
		gobBufferPool.Put(writer)
	}()

	if err := gob.NewEncoder(writer).Encode(resp); err != nil {
		slog.Error("error encoding cache",
			logging.FieldCaller, "handler:SaveCachedResponse",
			"hkey", hkey,
			logging.FieldError, err)
		return err
	}

	// Copy data before returning buffer to pool
	data := make([]byte, writer.Len())
	copy(data, writer.Bytes())

	// Background context is intentional here: SaveCachedResponse is called from
	// a background goroutine after the response has already been sent to the client.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := store.PutWithExpires(ctx, "response", hkey, bytes.NewReader(data), d); err != nil {
		slog.Error("error storing response",
			logging.FieldCaller, "handler:SaveCachedResponse",
			"hkey", hkey,
			logging.FieldError, err)
		return err
	}

	return nil
}
