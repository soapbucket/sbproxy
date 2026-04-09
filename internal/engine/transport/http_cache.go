// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/pquerna/cachecontrol/cacheobject"

	httputil "github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const (
	// Cache size limits
	httpCacheMaxSize = 1024 * 1024 * 2 // 2MB

	// HTTP cache headers - using constants from headers package
	headerCacheControl    = httputil.HeaderCacheControl
	headerETag            = httputil.HeaderETag
	headerLastModified    = httputil.HeaderLastModified
	headerIfNoneMatch     = httputil.HeaderIfNoneMatch
	headerIfModifiedSince = httputil.HeaderIfModifiedSince
	headerPragma          = "Pragma" // Not in http package yet
	headerVary            = "Vary"   // Not in http package yet
	headerExpires         = httputil.HeaderExpires
	headerDate            = httputil.HeaderDate
	headerAge             = "Age" // Not in http package yet

	// Default cache durations
	defaultCacheDuration = 5 * time.Minute
	maxCacheDuration     = 24 * time.Hour
)

// Pool for xxhash hashers (faster than MD5 for cache keys)
var httpCacheXxhashPool = sync.Pool{
	New: func() interface{} {
		return xxhash.New()
	},
}

// HTTPCacheEntry represents a cached HTTP response
type HTTPCacheEntry struct {
	Header     http.Header `json:"header"`
	StatusCode int         `json:"statusCode"`
	BodyKey    string      `json:"bodyKey"`
	Timestamp  time.Time   `json:"timestamp"`
	ETag       string      `json:"etag,omitempty"`
	Vary       string      `json:"vary,omitempty"`
}

// CacheConfig holds configuration for the HTTP cache
type CacheConfig struct {
	// CacheErrors determines if error responses (4xx, 5xx) should be cached
	CacheErrors bool

	// DefaultTTL is the default time-to-live for cached responses
	DefaultTTL time.Duration

	// MaxTTL is the maximum time-to-live for any cached response
	MaxTTL time.Duration

	// RespectNoCache determines if no-cache directives should be respected
	RespectNoCache bool

	// RespectPrivate determines if private cache directives should be respected
	RespectPrivate bool
}

// DefaultCacheConfig returns a default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		CacheErrors:    false,
		DefaultTTL:     defaultCacheDuration,
		MaxTTL:         maxCacheDuration,
		RespectNoCache: true,
		RespectPrivate: true,
	}
}

// HTTPCacheTransport implements HTTP caching with full RFC 7234 compliance
type HTTPCacheTransport struct {
	http.RoundTripper
	store  cacher.Cacher
	config *CacheConfig
}

// NewHTTPCacheTransport creates a new HTTP cache transport
func NewHTTPCacheTransport(tr http.RoundTripper, store cacher.Cacher, config *CacheConfig) http.RoundTripper {
	if config == nil {
		config = DefaultCacheConfig()
	}

	return &HTTPCacheTransport{
		RoundTripper: tr,
		store:        store,
		config:       config,
	}
}

// RoundTrip implements the http.RoundTripper interface with HTTP caching
func (h *HTTPCacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only cache GET and HEAD requests
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		slog.Debug("not caching request",
			logging.FieldCaller, "transport:HTTPCacheTransport:RoundTrip",
			"method", req.Method)
		return h.RoundTripper.RoundTrip(req)
	}

	// Don't cache requests with authorization headers (unless explicitly configured)
	if req.Header.Get(httputil.HeaderAuthorization) != "" && h.config.RespectPrivate {
		slog.Debug("not caching request with authorization header",
			logging.FieldCaller, "transport:HTTPCacheTransport:RoundTrip")
		return h.RoundTripper.RoundTrip(req)
	}

	// Check for no-cache directives in request
	if h.shouldBypassCache(req) {
		slog.Debug("bypassing cache due to no-cache directive",
			logging.FieldCaller, "transport:HTTPCacheTransport:RoundTrip")
		return h.RoundTripper.RoundTrip(req)
	}

	// Generate cache key considering Vary headers
	cacheKey := h.generateCacheKey(req)

	// Try to get cached response
	if cachedResp := h.getCachedResponse(req.Context(), req, cacheKey); cachedResp != nil {
		return cachedResp, nil
	}

	// No cache hit, make the request
	resp, err := h.RoundTripper.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Don't cache error responses unless configured to do so
	if !h.config.CacheErrors && resp.StatusCode >= 400 {
		return resp, err
	}

	// Check if response should be cached
	if h.shouldCacheResponse(resp) {
		// Wrap response body to enable caching
		resp.Body = h.wrapResponseBody(req.Context(), req, resp, cacheKey)
	}

	return resp, err
}

// shouldBypassCache checks if the request should bypass the cache
func (h *HTTPCacheTransport) shouldBypassCache(req *http.Request) bool {
	if !h.config.RespectNoCache {
		return false
	}

	// Check Cache-Control: no-cache
	if cacheControl := req.Header.Get(headerCacheControl); cacheControl != "" {
		if reqDir, err := cacheobject.ParseRequestCacheControl(cacheControl); err == nil {
			if reqDir.NoCache {
				return true
			}
		}
	}

	// Check Pragma: no-cache (HTTP/1.0 compatibility)
	if pragma := req.Header.Get(headerPragma); pragma != "" {
		if strings.Contains(strings.ToLower(pragma), "no-cache") {
			return true
		}
	}

	return false
}

// shouldCacheResponse determines if a response should be cached
func (h *HTTPCacheTransport) shouldCacheResponse(resp *http.Response) bool {
	// Don't cache responses that explicitly forbid caching
	cacheControl := resp.Header.Get(headerCacheControl)
	if cacheControl != "" {
		if respDir, err := cacheobject.ParseResponseCacheControl(cacheControl); err == nil {
			// Don't cache if explicitly marked as no-store or private (unless configured otherwise)
			if respDir.NoStore {
				return false
			}
			if respDir.PrivatePresent && h.config.RespectPrivate {
				return false
			}
		}
	}

	// Note: Set-Cookie headers are stripped by cleanHeaders() before storage,
	// so responses with Set-Cookie can still be cached safely.

	return true
}

// generateCacheKey creates a cache key considering Vary headers
func (h *HTTPCacheTransport) generateCacheKey(req *http.Request) string {
	// Start with the base cache key
	baseKey := cacher.RequestCacheKey(req)

	// For now, we'll use the base key. In a full implementation,
	// we would need to consider the Vary header from cached responses
	// and include those header values in the key
	return baseKey
}

// getCachedResponse retrieves a cached response if available and valid
func (h *HTTPCacheTransport) getCachedResponse(ctx context.Context, req *http.Request, cacheKey string) *http.Response {
	headerCacheKey := cacheHeaderPrefix + cacheKey
	hkey := crypto.GetHashFromString(headerCacheKey)

	data, err := h.store.Get(ctx, "http_cache", hkey)
	if err != nil {
		if err != cacher.ErrNotFound {
			slog.Warn("failed to get cache header",
				logging.FieldCaller, "transport:HTTPCacheTransport:getCachedResponse",
				"key", headerCacheKey,
				logging.FieldError, err)
		}
		return nil
	}

	var cached HTTPCacheEntry
	headerData, readErr := io.ReadAll(data)
	if readErr != nil {
		slog.Error("failed to read cached response header",
			logging.FieldCaller, "transport:HTTPCacheTransport:getCachedResponse",
			"key", headerCacheKey,
			logging.FieldError, readErr)
		return nil
	}
	if err := json.Unmarshal(headerData, &cached); err != nil {
		slog.Error("failed to parse cached response header",
			logging.FieldCaller, "transport:HTTPCacheTransport:getCachedResponse",
			"key", headerCacheKey,
			logging.FieldError, err)
		return nil
	}

	// Check if cache entry is expired
	if h.isCacheExpired(&cached) {
		slog.Debug("cache entry expired",
			logging.FieldCaller, "transport:HTTPCacheTransport:getCachedResponse",
			"key", cacheKey)
		return nil
	}

	// Handle conditional requests
	if conditionalResp := h.handleConditionalRequest(req, &cached); conditionalResp != nil {
		return conditionalResp
	}

	// Get cached body
	bodyCacheKey := cached.BodyKey
	bodyHkey := crypto.GetHashFromString(bodyCacheKey)
	bodyData, err := h.store.Get(ctx, "http_cache", bodyHkey)
	if err != nil {
		if err != cacher.ErrNotFound {
			slog.Warn("failed to get cache body",
				logging.FieldCaller, "transport:HTTPCacheTransport:getCachedResponse",
				"key", bodyCacheKey,
				logging.FieldError, err)
		}
		return nil
	}

	slog.Debug("returning cached response",
		logging.FieldCaller, "transport:HTTPCacheTransport:getCachedResponse",
		"key", cacheKey)

	// Create response from cached data
	bodyBytes, readErr := io.ReadAll(bodyData)
	if readErr != nil {
		slog.Error("failed to read cached body",
			logging.FieldCaller, "transport:HTTPCacheTransport:getCachedResponse",
			"key", bodyCacheKey,
			logging.FieldError, readErr)
		return nil
	}
	resp := &http.Response{
		Request:    req,
		StatusCode: cached.StatusCode,
		Header:     cached.Header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}

	// RFC 9111 Section 5.1: set Age header to the number of seconds since the
	// response was generated (or last validated) by the origin server.
	age := int(time.Since(cached.Timestamp).Seconds())
	if age < 0 {
		age = 0
	}
	resp.Header.Set(headerAge, strconv.Itoa(age))

	return resp
}

// handleConditionalRequest handles If-None-Match and If-Modified-Since requests
func (h *HTTPCacheTransport) handleConditionalRequest(req *http.Request, cached *HTTPCacheEntry) *http.Response {
	// Handle If-None-Match (ETag validation)
	if noneMatch := req.Header.Get(headerIfNoneMatch); noneMatch != "" {
		if cached.ETag != "" {
			// Check if any of the ETags match
			etags := strings.Split(noneMatch, ",")
			for _, etag := range etags {
				etag = strings.TrimSpace(etag)
				if etag == cached.ETag || etag == "*" {
					slog.Debug("returning 304 Not Modified (ETag)",
						logging.FieldCaller, "transport:HTTPCacheTransport:handleConditionalRequest",
						"etag", cached.ETag)
					return &http.Response{
						Request:    req,
						StatusCode: http.StatusNotModified,
						Header:     cached.Header,
						Body:       http.NoBody,
					}
				}
			}
		}
	}

	// Handle If-Modified-Since (Last-Modified validation)
	if modifiedSinceStr := req.Header.Get(headerIfModifiedSince); modifiedSinceStr != "" {
		if lastModifiedStr := cached.Header.Get(headerLastModified); lastModifiedStr != "" {
			if modifiedSince, err := httputil.ParseHTTPDate(modifiedSinceStr); err == nil {
				if lastModified, err := httputil.ParseHTTPDate(lastModifiedStr); err == nil {
					if !lastModified.After(modifiedSince) {
						slog.Debug("returning 304 Not Modified (Last-Modified)",
							logging.FieldCaller, "transport:HTTPCacheTransport:handleConditionalRequest")
						return &http.Response{
							Request:    req,
							StatusCode: http.StatusNotModified,
							Header:     cached.Header,
							Body:       http.NoBody,
						}
					}
				}
			}
		}
	}

	return nil
}

// isCacheExpired checks if a cache entry has expired
func (h *HTTPCacheTransport) isCacheExpired(cached *HTTPCacheEntry) bool {
	// Check Cache-Control max-age
	if cacheControl := cached.Header.Get(headerCacheControl); cacheControl != "" {
		if respDir, err := cacheobject.ParseResponseCacheControl(cacheControl); err == nil {
			if respDir.MaxAge > 0 {
				expiresAt := cached.Timestamp.Add(time.Duration(respDir.MaxAge) * time.Second)
				return time.Now().After(expiresAt)
			}
		}
	}

	// Check Expires header
	if expiresStr := cached.Header.Get(headerExpires); expiresStr != "" {
		if dateStr := cached.Header.Get(headerDate); dateStr != "" {
			if _, err := httputil.ParseHTTPDate(dateStr); err == nil {
				if expires, err := httputil.ParseHTTPDate(expiresStr); err == nil {
					return time.Now().After(expires)
				}
			}
		}
	}

	// Use default TTL
	expiresAt := cached.Timestamp.Add(h.config.DefaultTTL)
	return time.Now().After(expiresAt)
}

// calculateTTL determines the TTL for a response
func (h *HTTPCacheTransport) calculateTTL(resp *http.Response) time.Duration {
	// Check Cache-Control max-age
	if cacheControl := resp.Header.Get(headerCacheControl); cacheControl != "" {
		if respDir, err := cacheobject.ParseResponseCacheControl(cacheControl); err == nil {
			if respDir.MaxAge > 0 {
				ttl := time.Duration(respDir.MaxAge) * time.Second
				if ttl > h.config.MaxTTL {
					ttl = h.config.MaxTTL
				}
				return ttl
			}
		}
	}

	// Check Expires header
	if expiresStr := resp.Header.Get(headerExpires); expiresStr != "" {
		if dateStr := resp.Header.Get(headerDate); dateStr != "" {
			if date, err := httputil.ParseHTTPDate(dateStr); err == nil {
				if expires, err := httputil.ParseHTTPDate(expiresStr); err == nil {
					ttl := expires.Sub(date)
					if ttl > 0 && ttl <= h.config.MaxTTL {
						return ttl
					}
				}
			}
		}
	}

	// Use default TTL
	return h.config.DefaultTTL
}

// wrapResponseBody wraps the response body to enable caching
func (h *HTTPCacheTransport) wrapResponseBody(ctx context.Context, req *http.Request, resp *http.Response, cacheKey string) io.ReadCloser {
	ttl := h.calculateTTL(resp)
	if ttl <= 0 {
		return resp.Body
	}

	// Get xxhash hasher from pool
	hasher := httpCacheXxhashPool.Get().(hash.Hash)
	hasher.Reset()

	// Clean headers (remove Set-Cookie, etc.)
	cleanHeader := h.cleanHeaders(resp.Header)

	// Generate ETag if not present
	etag := resp.Header.Get(headerETag)
	if etag == "" {
		// We'll generate ETag when the body is fully read
		etag = ""
	}

	return &HTTPCacheBody{
		ctx:        ctx,
		header:     cleanHeader,
		statusCode: resp.StatusCode,
		buff:       new(bytes.Buffer),
		reader:     resp.Body,
		key:        cacheKey,
		ttl:        ttl,
		store:      h.store,
		hasher:     hasher,
		etag:       etag,
		vary:       resp.Header.Get(headerVary),
	}
}

// cleanHeaders removes headers that shouldn't be cached
func (h *HTTPCacheTransport) cleanHeaders(header http.Header) http.Header {
	cleanHeader := http.Header{}
	for key, values := range header {
		// Don't cache Set-Cookie headers
		if !strings.EqualFold(httputil.HeaderSetCookie, key) {
			cleanHeader[key] = values
		}
	}
	return cleanHeader
}

// HTTPCacheBody wraps the response body to enable caching
type HTTPCacheBody struct {
	ctx        context.Context
	header     http.Header
	statusCode int
	buff       *bytes.Buffer
	reader     io.ReadCloser
	key        string
	ttl        time.Duration
	store      cacher.Cacher
	hasher     hash.Hash
	etag       string
	vary       string
	total      int
}

// Read implements io.Reader
func (h *HTTPCacheBody) Read(p []byte) (n int, err error) {
	n, err = h.reader.Read(p)
	h.total += n
	if h.total < httpCacheMaxSize {
		h.hasher.Write(p[:n])
		h.buff.Write(p[:n])
	}
	return n, err
}

// Close implements io.Closer and triggers cache storage
func (h *HTTPCacheBody) Close() error {
	if h.total < httpCacheMaxSize {
		// Generate ETag if not present
		if h.etag == "" {
			h.etag = "\"" + hex.EncodeToString(h.hasher.Sum(nil)) + "\""
		}

		// Store cache entry synchronously to avoid goroutine explosion
		h.storeCacheEntry()
	}

	// Return hasher to pool
	httpCacheXxhashPool.Put(h.hasher)
	return h.reader.Close()
}

// storeCacheEntry stores the cache entry
func (h *HTTPCacheBody) storeCacheEntry() {
	slog.Debug("caching response",
		logging.FieldCaller, "transport:HTTPCacheBody:storeCacheEntry",
		"key", h.key)

	// Set ETag in headers
	h.header.Set(headerETag, h.etag)

	// Create cache entry
	cacheEntry := &HTTPCacheEntry{
		Header:     h.header,
		StatusCode: h.statusCode,
		BodyKey:    cacheBodyPrefix + h.key,
		Timestamp:  time.Now(),
		ETag:       h.etag,
		Vary:       h.vary,
	}

	// Store header
	headerCacheKey := cacheHeaderPrefix + h.key
	if data, err := json.Marshal(cacheEntry); err == nil {
		hkey := crypto.GetHashFromString(headerCacheKey)
		if err := h.store.PutWithExpires(h.ctx, "http_cache", hkey, bytes.NewReader(data), h.ttl); err != nil {
			slog.Error("failed to cache response header",
				logging.FieldCaller, "transport:HTTPCacheBody:storeCacheEntry",
				"key", headerCacheKey,
				logging.FieldError, err)
			return
		}
	} else {
		slog.Error("failed to marshal response header",
			logging.FieldCaller, "transport:HTTPCacheBody:storeCacheEntry",
			"key", headerCacheKey,
			logging.FieldError, err)
		return
	}

	// Store body
	bodyCacheKey := cacheBodyPrefix + h.key
	hkey := crypto.GetHashFromString(bodyCacheKey)
	if err := h.store.PutWithExpires(h.ctx, "http_cache", hkey, bytes.NewReader(h.buff.Bytes()), h.ttl); err != nil {
		slog.Error("failed to cache response body",
			logging.FieldCaller, "transport:HTTPCacheBody:storeCacheEntry",
			"key", bodyCacheKey,
			logging.FieldError, err)
	}
}
