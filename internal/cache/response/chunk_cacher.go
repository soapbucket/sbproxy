// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ChunkCacher provides unified chunk caching middleware
// Supports both URL-based and signature-based (fingerprint) caching
type ChunkCacher struct {
	cache   cacher.Cacher
	config  *config.ChunkCacheConfig
	matcher *SignatureMatcher
}

// NewChunkCacher creates a new chunk cacher middleware
func NewChunkCacher(cache cacher.Cacher, cfg *config.ChunkCacheConfig) (*ChunkCacher, error) {
	cc := &ChunkCacher{
		cache:  cache,
		config: cfg,
	}

	// Initialize signature matcher if signature cache is enabled
	if cfg.SignatureCache.Enabled && len(cfg.SignatureCache.Signatures) > 0 {
		matcher, err := NewSignatureMatcher(cfg.SignatureCache.Signatures)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize signature matcher: %w", err)
		}
		cc.matcher = matcher
	}

	return cc, nil
}

// Middleware returns the chunk caching middleware handler
func (cc *ChunkCacher) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Skip chunk caching for non-standard methods
		// Chunk caching is designed for GET requests with complete responses
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			slog.Debug("chunk cache: skipping non-GET/HEAD method", "method", req.Method, "url", req.URL.String())
			next.ServeHTTP(rw, req)
			return
		}

		// Check if response writer supports flushing
		flusher, ok := rw.(http.Flusher)
		if !ok {
			slog.Debug("chunk cache: response writer does not support flushing", "url", req.URL.String())
			next.ServeHTTP(rw, req)
			return
		}

		// Check cache control headers
		if !cc.shouldCache(req) {
			slog.Debug("chunk cache: skipping due to cache control", "url", req.URL.String())
			next.ServeHTTP(rw, req)
			return
		}

		requestData := reqctx.GetRequestData(req.Context())
		if requestData.NoCache {
			slog.Debug("chunk cache: bypassing cache due to no-cache flag", "url", req.URL.String())
			next.ServeHTTP(rw, req)
			return
		}

		// Try signature-based cache first (fingerprint)
		if cc.config.SignatureCache.Enabled {
			if chunk, cacheKey := cc.checkSignatureCache(req); chunk != nil {
				slog.Debug("chunk cache: signature hit", "url", req.URL.String(), "size", len(chunk.Body), "cache_key", cacheKey)
				metric.ChunkCacheOperation("signature", "serve", "hit")
				cc.serveChunkAndContinue(rw, flusher, chunk, next, req, cacheKey)
				return
			}
		}

		// Try URL-based cache
		if cc.config.URLCache.Enabled {
			if chunk, cacheKey := cc.checkURLCache(req); chunk != nil {
				slog.Debug("chunk cache: URL hit", "url", req.URL.String(), "size", len(chunk.Body), "cache_key", cacheKey)
				metric.ChunkCacheOperation("url", "get", "hit")
				if chunk.IsComplete {
					// Full response cached
					cc.serveCompleteResponse(rw, chunk, req, cacheKey)
					return
				}
				// Partial response - serve chunk and continue
				cc.serveChunkAndContinue(rw, flusher, chunk, next, req, cacheKey)
				return
			}
		}

		// Cache miss - get response writer wrapper from pool to capture and examine response
		metric.ChunkCacheOperation("url", "get", "miss")
		crw := getChunkCachingWriter(rw, flusher, cc.cache, cc.config, cc.matcher, req, cc.getMaxExamineBytes())

		next.ServeHTTP(crw, req)

		// Process and cache after response completes
		crw.processAndCache()

		// Return writer to pool
		putChunkCachingWriter(crw)
	})
}

// shouldCache checks if the request should be cached based on cache control headers
func (cc *ChunkCacher) shouldCache(req *http.Request) bool {
	if cc.config.IgnoreNoCache {
		return true
	}

	cacheControl, err := cacheobject.ParseRequestCacheControl(req.Header.Get("Cache-Control"))
	if err != nil {
		return true // Assume cacheable if we can't parse
	}

	return !cacheControl.NoCache
}

// checkSignatureCache checks for a cached prefix based on signature
// Returns the cached chunk and the cache key used
func (cc *ChunkCacher) checkSignatureCache(req *http.Request) (*CachedChunk, string) {
	// Get request context data
	requestData := reqctx.GetRequestData(req.Context())
	if requestData == nil || requestData.Config == nil {
		return nil, ""
	}

	configData := reqctx.ConfigParams(requestData.Config)
	workspaceID := configData.GetWorkspaceID()
	configID := configData.GetConfigID()

	// Try each configured signature
	for _, sig := range cc.config.SignatureCache.Signatures {
		cacheKey := generateSignatureCacheKey(configID, workspaceID, &sig)

		// Try to get cached prefix
		reader, err := cc.cache.Get(req.Context(), "chunk", cacheKey)
		if err != nil {
			continue
		}

		// Read cached chunk
		chunk, err := deserializeChunk(reader)
		if err != nil {
			slog.Debug("chunk cache: failed to deserialize chunk", "cache_key", cacheKey, "error", err)
			continue
		}

		if len(chunk.Body) > 0 {
			metric.FingerprintCacheOperation(configID, "get", "hit")
			return chunk, cacheKey
		}
	}

	metric.ChunkCacheOperation("signature", "get", "miss")
	return nil, ""
}

// checkURLCache checks for a cached response by URL
// Returns the cached chunk and the cache key used
func (cc *ChunkCacher) checkURLCache(req *http.Request) (*CachedChunk, string) {
	cacheKey := normalizeURL(req)

	// Try to get cached response
	reader, err := cc.cache.Get(req.Context(), "chunk", cacheKey)
	if err != nil {
		return nil, ""
	}

	chunk, err := deserializeChunk(reader)
	if err != nil {
		slog.Debug("chunk cache: failed to deserialize chunk", "cache_key", cacheKey, "error", err)
		return nil, ""
	}

	return chunk, cacheKey
}

// serveChunkAndContinue serves a cached chunk and continues to proxy for the rest
func (cc *ChunkCacher) serveChunkAndContinue(rw http.ResponseWriter, flusher http.Flusher,
	chunk *CachedChunk, next http.Handler, req *http.Request, cacheKey string) {

	// Set headers from cached chunk
	for key, values := range chunk.Headers {
		rw.Header()[key] = values
	}

	// Enable chunked encoding for HTTP/1.1 and HTTP/2
	// HTTP/3 doesn't support Transfer-Encoding header (uses QUIC streams)
	if req.ProtoMajor < 3 {
		rw.Header().Set("Transfer-Encoding", "chunked")
	}
	rw.Header().Del("Content-Length")
	if rw.Header().Get("X-Content-Type-Options") == "" {
		rw.Header().Set("X-Content-Type-Options", "nosniff")
	}

	// Add debug headers if enabled
	if requestData := reqctx.GetRequestData(req.Context()); requestData != nil && requestData.Debug {
		rw.Header().Set(httputil.HeaderXSbCacheKey, cacheKey)

		// Determine cache status
		if strings.HasPrefix(cacheKey, "signature:") {
			// Signature cache is always partial/streaming
			rw.Header().Set("X-Cache", "HIT-SIGNATURE")
		} else {
			// URL cache: check freshness
			ttl := cc.config.URLCache.TTL.Duration
			if ttl == 0 {
				ttl = 1 * time.Hour // Default
			}
			age := time.Since(chunk.CachedAt)
			if age > ttl {
				rw.Header().Set("X-Cache", "HIT-STALE")
			} else {
				rw.Header().Set("X-Cache", "HIT")
			}
		}
	}

	// Write cached prefix
	n, err := rw.Write(chunk.Body)
	if err != nil {
		slog.Error("chunk cache: error writing cached prefix", "error", err)
		http.Error(rw, "error writing cached prefix", http.StatusInternalServerError)
		return
	}

	// FLUSH IMMEDIATELY - Key for TTFB improvement
	flusher.Flush()

	slog.Debug("chunk cache: flushed cached prefix", "bytes", n, "cache_key", cacheKey)

	// Continue with wrapped writer that tracks offset
	// Use ChunkContinuationWriter which doesn't try to send headers again
	crw := &ChunkContinuationWriter{
		rw:             rw,
		offset:         n, // Skip bytes already sent
		flusher:        flusher,
		headersWritten: true, // Headers already sent with cached chunk
	}

	slog.Debug("chunk cache: continuing proxy for rest of response",
		"cached_bytes", n,
		"cache_key", cacheKey)

	next.ServeHTTP(crw, req)

	slog.Debug("chunk cache: completed streaming response",
		"cached_bytes", n,
		"additional_bytes", crw.bytesWritten,
		"total_bytes", n+crw.bytesWritten)
}

// serveCompleteResponse serves a complete cached response
func (cc *ChunkCacher) serveCompleteResponse(rw http.ResponseWriter, chunk *CachedChunk, req *http.Request, cacheKey string) {
	// Set headers
	for key, values := range chunk.Headers {
		rw.Header()[key] = values
	}

	// Add debug headers if enabled
	if requestData := reqctx.GetRequestData(req.Context()); requestData != nil && requestData.Debug {
		rw.Header().Set(httputil.HeaderXSbCacheKey, cacheKey)

		// Determine cache status
		if strings.HasPrefix(cacheKey, "signature:") {
			// Signature cache (shouldn't reach here for complete responses, but handle it)
			rw.Header().Set("X-Cache", "HIT-SIGNATURE")
		} else {
			// URL cache: check freshness
			ttl := cc.config.URLCache.TTL.Duration
			if ttl == 0 {
				ttl = 1 * time.Hour // Default
			}
			age := time.Since(chunk.CachedAt)
			if age > ttl {
				rw.Header().Set("X-Cache", "HIT-STALE")
			} else {
				rw.Header().Set("X-Cache", "HIT")
			}
		}
	}

	// Write status and body
	if chunk.Status > 0 {
		rw.WriteHeader(chunk.Status)
	}
	_, _ = rw.Write(chunk.Body)

	metric.ChunkCacheOperation("url", "serve", "complete")
}

// getMaxExamineBytes returns the maximum bytes to examine for signatures
func (cc *ChunkCacher) getMaxExamineBytes() int {
	if cc.config.SignatureCache.MaxExamineBytes > 0 {
		return cc.config.SignatureCache.MaxExamineBytes
	}
	return 8192 // Default
}

// chunkCachingWriter captures response data and examines it for caching
type chunkCachingWriter struct {
	rw      http.ResponseWriter
	flusher http.Flusher
	cache   cacher.Cacher
	config  *config.ChunkCacheConfig
	matcher *SignatureMatcher
	req     *http.Request

	// Response capture
	buffer        *bytes.Buffer
	examineBuffer []byte
	headers       http.Header
	status        int
	bytesWritten  int
	examined      bool
}

// chunkCachingWriterPool reuses chunkCachingWriter structs to avoid per-request heap allocation.
var chunkCachingWriterPool = sync.Pool{
	New: func() any {
		return &chunkCachingWriter{
			buffer:  &bytes.Buffer{},
			headers: make(http.Header),
		}
	},
}

func getChunkCachingWriter(rw http.ResponseWriter, flusher http.Flusher, cache cacher.Cacher, cfg *config.ChunkCacheConfig, matcher *SignatureMatcher, req *http.Request, maxExamineBytes int) *chunkCachingWriter {
	crw := chunkCachingWriterPool.Get().(*chunkCachingWriter)
	crw.rw = rw
	crw.flusher = flusher
	crw.cache = cache
	crw.config = cfg
	crw.matcher = matcher
	crw.req = req
	crw.buffer.Reset()
	if cap(crw.examineBuffer) >= maxExamineBytes {
		crw.examineBuffer = crw.examineBuffer[:0]
	} else {
		crw.examineBuffer = make([]byte, 0, maxExamineBytes)
	}
	clear(crw.headers)
	crw.status = 0
	crw.bytesWritten = 0
	crw.examined = false
	return crw
}

func putChunkCachingWriter(crw *chunkCachingWriter) {
	crw.rw = nil
	crw.flusher = nil
	crw.cache = nil
	crw.config = nil
	crw.matcher = nil
	crw.req = nil
	chunkCachingWriterPool.Put(crw)
}

// Header performs the header operation on the chunkCachingWriter.
func (crw *chunkCachingWriter) Header() http.Header {
	return crw.rw.Header()
}

// WriteHeader performs the write header operation on the chunkCachingWriter.
func (crw *chunkCachingWriter) WriteHeader(status int) {
	crw.status = status
	crw.rw.WriteHeader(status)
}

// Write performs the write operation on the chunkCachingWriter.
func (crw *chunkCachingWriter) Write(p []byte) (int, error) {
	// Write to client
	n, err := crw.rw.Write(p)
	crw.bytesWritten += n

	// Capture for examination (signature matching)
	if !crw.examined && crw.matcher != nil && crw.config.SignatureCache.Enabled {
		maxExamine := cap(crw.examineBuffer)
		if len(crw.examineBuffer) < maxExamine {
			remaining := maxExamine - len(crw.examineBuffer)
			toAppend := n
			if toAppend > remaining {
				toAppend = remaining
			}
			crw.examineBuffer = append(crw.examineBuffer, p[:toAppend]...)

			// Mark as examined once we have enough data
			if len(crw.examineBuffer) >= maxExamine {
				crw.examined = true
			}
		}
	}

	// Buffer for URL-based caching (if enabled)
	if crw.config.URLCache.Enabled {
		crw.buffer.Write(p[:n])
	}

	return n, err
}

// Flush performs the flush operation on the chunkCachingWriter.
func (crw *chunkCachingWriter) Flush() {
	if crw.flusher != nil {
		crw.flusher.Flush()
	}
}

// processAndCache examines the captured response and caches appropriately
func (crw *chunkCachingWriter) processAndCache() {
	// Capture headers
	crw.headers = crw.rw.Header().Clone()

	ctx := crw.req.Context()

	// Process signature-based caching
	if crw.config.SignatureCache.Enabled && len(crw.examineBuffer) > 0 {
		crw.processSignatureCache(ctx)
	}

	// Process URL-based caching
	if crw.config.URLCache.Enabled && crw.buffer.Len() > 0 {
		crw.processURLCache(ctx)
	}
}

// processSignatureCache examines response for signature match and caches prefix
func (crw *chunkCachingWriter) processSignatureCache(ctx context.Context) {
	contentType, _, _ := mime.ParseMediaType(crw.headers.Get("Content-Type"))

	// Check if content type is eligible
	if !isEligibleContentType(contentType, crw.config.SignatureCache.ContentTypes) {
		return
	}

	// Try to match signature
	if crw.matcher == nil {
		return
	}

	matchedSig, prefixLen := crw.matcher.Match(crw.examineBuffer)
	if matchedSig == nil || prefixLen == 0 {
		slog.Debug("chunk cache: no signature match", "content_type", contentType)
		return
	}

	// Extract prefix
	if prefixLen > len(crw.examineBuffer) {
		prefixLen = len(crw.examineBuffer)
	}
	prefix := crw.examineBuffer[:prefixLen]

	// Get tenant and config IDs
	requestData := reqctx.GetRequestData(ctx)
	if requestData == nil || requestData.Config == nil {
		return
	}

	configData := reqctx.ConfigParams(requestData.Config)
	configID := configData.GetConfigID()
	workspaceID := configData.GetWorkspaceID()

	// Generate cache key
	cacheKey := generateSignatureCacheKey(configID, workspaceID, matchedSig)

	// Determine TTL
	ttl := matchedSig.CacheTTL.Duration
	if ttl == 0 {
		ttl = crw.config.SignatureCache.DefaultTTL.Duration
		if ttl == 0 {
			ttl = 30 * time.Minute
		}
	}

	// Create chunk
	chunk := &CachedChunk{
		Headers:    crw.headers.Clone(),
		Body:       prefix,
		IsComplete: false,
		CachedAt:   time.Now(),
	}

	// Serialize and cache
	data := serializeChunk(chunk)
	if err := crw.cache.PutWithExpires(ctx, "chunk", cacheKey, bytes.NewReader(data), ttl); err != nil {
		slog.Error("chunk cache: failed to cache signature prefix",
			"error", err, "cache_key", cacheKey, "signature", matchedSig.Name)
		metric.ChunkCacheOperation("signature", "set", "error")
	} else {
		slog.Debug("chunk cache: cached signature prefix",
			"cache_key", cacheKey, "signature", matchedSig.Name, "size", len(prefix), "ttl", ttl)
		metric.FingerprintCacheOperation(configID, "store", "success")
		metric.ChunkCacheOperation("signature", "set", "complete")
	}
}

// processURLCache caches the full response by URL
func (crw *chunkCachingWriter) processURLCache(ctx context.Context) {
	// Don't cache if response says no-store
	if !crw.config.IgnoreNoCache {
		if cc, err := cacheobject.ParseResponseCacheControl(crw.headers.Get("Cache-Control")); err == nil {
			if cc.NoStore {
				slog.Debug("chunk cache: skipping URL cache due to no-store", "url", normalizeURL(crw.req))
				return
			}
		}
	}

	// Determine TTL
	ttl := crw.config.URLCache.TTL.Duration
	if ttl == 0 {
		ttl = 1 * time.Hour
	}

	cacheKey := normalizeURL(crw.req)

	// Create chunk
	chunk := &CachedChunk{
		Headers:    crw.headers.Clone(),
		Body:       crw.buffer.Bytes(),
		Status:     crw.status,
		IsComplete: true,
		CachedAt:   time.Now(),
	}

	// Serialize and cache
	data := serializeChunk(chunk)
	if err := crw.cache.PutWithExpires(ctx, "chunk", cacheKey, bytes.NewReader(data), ttl); err != nil {
		slog.Error("chunk cache: failed to cache URL response",
			"error", err, "cache_key", cacheKey)
		metric.ChunkCacheOperation("url", "set", "error")
	} else {
		slog.Debug("chunk cache: cached URL response",
			"cache_key", cacheKey, "size", len(chunk.Body), "ttl", ttl)
		metric.ChunkCacheOperation("url", "set", "complete")
	}
}

// CachedChunk represents a cached chunk (prefix or full response)
type CachedChunk struct {
	Headers    http.Header
	Body       []byte
	Status     int
	IsComplete bool // True if this is a full response, false if just a prefix
	CachedAt   time.Time
}

// generateSignatureCacheKey generates a cache key for signature-based caching
func generateSignatureCacheKey(configID, workspaceID string, sig *config.SignaturePattern) string {
	// Format: chunk:signature:workspace:{workspaceID}:config:{configID}:sig:{name}
	parts := []string{"signature"}
	if workspaceID != "" {
		parts = append(parts, "workspace:"+workspaceID)
	}
	if configID != "" {
		parts = append(parts, "config:"+configID)
	}
	parts = append(parts, "sig:"+sig.Name)
	return strings.Join(parts, ":")
}

// normalizeURL normalizes a URL for cache key generation
// Includes tenant and config IDs for proper cache isolation
func normalizeURL(req *http.Request) string {
	parts := []string{"url"}

	// Add workspace_id and config_id from RequestData.Config
	if requestData := reqctx.GetRequestData(req.Context()); requestData != nil && requestData.Config != nil {
		configParams := reqctx.ConfigParams(requestData.Config)
		if workspaceID := configParams.GetWorkspaceID(); workspaceID != "" {
			parts = append(parts, "workspace:"+workspaceID)
		}
		if configID := configParams.GetConfigID(); configID != "" {
			parts = append(parts, "config:"+configID)
		}
	}

	// Add the URL
	parts = append(parts, req.URL.String())

	return strings.Join(parts, ":")
}

// isEligibleContentType checks if a content type is eligible for caching
func isEligibleContentType(contentType string, eligibleTypes []string) bool {
	if len(eligibleTypes) == 0 {
		// Default to text/html
		return strings.HasPrefix(contentType, "text/html")
	}

	for _, et := range eligibleTypes {
		if strings.HasPrefix(contentType, et) {
			return true
		}
	}

	return false
}

// serializeChunk serializes a chunk for storage
func serializeChunk(chunk *CachedChunk) []byte {
	// Simple serialization - in production, use gob or protobuf
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	// Write format version
	_ = writer.WriteByte(1)

	// Write status
	_ = writer.WriteByte(byte(chunk.Status >> 8))
	_ = writer.WriteByte(byte(chunk.Status))

	// Write is_complete flag
	if chunk.IsComplete {
		_ = writer.WriteByte(1)
	} else {
		_ = writer.WriteByte(0)
	}

	// Write headers count
	_ = writer.WriteByte(byte(len(chunk.Headers)))
	for key, values := range chunk.Headers {
		_, _ = writer.WriteString(key + "\n")
		_ = writer.WriteByte(byte(len(values)))
		for _, value := range values {
			_, _ = writer.WriteString(value + "\n")
		}
	}

	// Write body length and body
	bodyLen := len(chunk.Body)
	_ = writer.WriteByte(byte(bodyLen >> 24))
	_ = writer.WriteByte(byte(bodyLen >> 16))
	_ = writer.WriteByte(byte(bodyLen >> 8))
	_ = writer.WriteByte(byte(bodyLen))
	_, _ = writer.Write(chunk.Body)

	writer.Flush()
	return buf.Bytes()
}

// deserializeChunk deserializes a chunk from storage
func deserializeChunk(r io.Reader) (*CachedChunk, error) {
	reader := bufio.NewReader(r)

	// Read format version
	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, fmt.Errorf("unsupported chunk format version: %d", version)
	}

	chunk := &CachedChunk{
		Headers: make(http.Header),
	}

	// Read status
	statusHigh, _ := reader.ReadByte()
	statusLow, _ := reader.ReadByte()
	chunk.Status = (int(statusHigh) << 8) | int(statusLow)

	// Read is_complete flag
	isComplete, _ := reader.ReadByte()
	chunk.IsComplete = isComplete == 1

	// Read headers
	headerCount, _ := reader.ReadByte()
	for i := 0; i < int(headerCount); i++ {
		key, _ := reader.ReadString('\n')
		key = strings.TrimSuffix(key, "\n")
		valueCount, _ := reader.ReadByte()
		values := make([]string, valueCount)
		for j := 0; j < int(valueCount); j++ {
			value, _ := reader.ReadString('\n')
			values[j] = strings.TrimSuffix(value, "\n")
		}
		chunk.Headers[key] = values
	}

	// Read body
	bodyLen1, _ := reader.ReadByte()
	bodyLen2, _ := reader.ReadByte()
	bodyLen3, _ := reader.ReadByte()
	bodyLen4, _ := reader.ReadByte()
	bodyLen := (int(bodyLen1) << 24) | (int(bodyLen2) << 16) | (int(bodyLen3) << 8) | int(bodyLen4)

	chunk.Body = make([]byte, bodyLen)
	_, _ = io.ReadFull(reader, chunk.Body)

	return chunk, nil
}
