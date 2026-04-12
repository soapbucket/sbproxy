// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/pquerna/cachecontrol/cacheobject"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	httputil "github.com/soapbucket/sbproxy/internal/httpkit/httputil"
)

const (
	maxCacheSize      = 1024 * 1024 * 2 // 2mb
	cacheHeaderPrefix = "cache.header:"
	cacheBodyPrefix   = "cache.body:"
)

// Pool for xxhash hashers (faster than MD5 for cache keys)
var xxhashPool = sync.Pool{
	New: func() interface{} {
		return xxhash.New()
	},
}

// CacherHeader represents a cacher header.
type CacherHeader struct {
	Header     http.Header `json:"header"`
	StatusCode int         `json:"statusCode"`
	BodyKey    string      `json:"bodyKey"`
}

// CacherBody represents a cacher body.
type CacherBody struct {
	header     http.Header
	statusCode int
	buff       *bytes.Buffer
	reader     io.ReadCloser
	key        string
	expires    time.Duration
	store      cacher.Cacher
	hasher     hash.Hash
	total      int
}

// Read performs the read operation on the CacherBody.
func (c *CacherBody) Read(p []byte) (n int, err error) {
	n, err = c.reader.Read(p)
	c.total += n
	if c.total < maxCacheSize {
		c.hasher.Write(p[:n])
		c.buff.Write(p[:n])
	}
	return n, err
}

// Close releases resources held by the CacherBody.
func (c *CacherBody) Close() error {
	if c.total < maxCacheSize {
		etag := fmt.Sprintf("%x", c.hasher.Sum(nil))

		// initiate a cache write
		func(etag, key string, header http.Header, statusCode int, expires time.Duration, body []byte, store cacher.Cacher) {
			slog.Debug("Caching response", "key", key)

			header.Set("ETag", etag)

			headerCacheKey := cacheHeaderPrefix + key
			bodyCacheKey := cacheBodyPrefix + key
			cacheHeader := &CacherHeader{
				Header:     header,
				StatusCode: statusCode,
				BodyKey:    bodyCacheKey,
			}

			if data, err := json.Marshal(cacheHeader); err == nil {
				hkey := crypto.GetHashFromString(headerCacheKey)
				if err := store.PutWithExpires(context.Background(), "cacher", hkey, bytes.NewReader(data), expires); err != nil {
					slog.Error("Failed to cache response header", "key", headerCacheKey, "error", err)
					return
				}
			} else {
				slog.Error("Failed to marshal response header", "key", headerCacheKey, "error", err)
				return
			}

			hkey := crypto.GetHashFromString(bodyCacheKey)
			if err := store.PutWithExpires(context.Background(), "cacher", hkey, bytes.NewReader(body), expires); err != nil {
				slog.Error("Failed to cache response body", "key", bodyCacheKey, "error", err)
			}

		}(etag, c.key, c.header, c.statusCode, c.expires, c.buff.Bytes(), c.store)
	}
	c.hasher.Reset()
	xxhashPool.Put(c.hasher)
	c.hasher = nil
	return c.reader.Close()
}

// CacherTransport represents a cacher transport.
type CacherTransport struct {
	http.RoundTripper

	cacheErrors bool
	store       cacher.Cacher
}

// RoundTrip performs the round trip operation on the CacherTransport.
func (c *CacherTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// only caching GET requests
	if req.Method != http.MethodGet {
		slog.Debug("not caching request", "method", req.Method)
		return c.RoundTripper.RoundTrip(req)
	}

	// don't cache requests with authorization headers
	if req.Header.Get(httputil.HeaderAuthorization) != "" {
		slog.Debug("not caching request with authorization header")
		return c.RoundTripper.RoundTrip(req)
	}

	key := cacher.RequestCacheKey(req)
	var cached CacherHeader

	headerCacheKey := cacheHeaderPrefix + key
	hkey := crypto.GetHashFromString(headerCacheKey)
	if reader, err := c.store.Get(context.Background(), "cacher", hkey); err == nil {
		data, readErr := io.ReadAll(reader)
		if readErr == nil {
			if err := json.Unmarshal(data, &cached); err != nil {
				slog.Error("failed to parse cached response header", "key", headerCacheKey, "error", err)
			}
		}
	}

	//ETag - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
	noneMatch := req.Header.Get(httputil.HeaderIfNoneMatch)
	etag := cached.Header.Get(httputil.HeaderETag)
	if etag != "" && noneMatch != "" && noneMatch == etag {
		slog.Debug("returning cached etag response", "key", key)
		// return etag response
		return &http.Response{
			Request:    req,
			StatusCode: http.StatusNotModified,
			Header:     cached.Header,
			Body:       http.NoBody,
		}, nil
	}

	//Last-Modified - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since
	modifiedSinceStr := req.Header.Get(httputil.HeaderIfModifiedSince)
	lastModifiedStr := cached.Header.Get(httputil.HeaderLastModified)
	if modifiedSinceStr != "" && lastModifiedStr != "" {
		if modifiedSince, err := httputil.ParseHTTPDate(modifiedSinceStr); err == nil {
			if lastModified, err := httputil.ParseHTTPDate(lastModifiedStr); err == nil && modifiedSince.After(lastModified) {
				slog.Debug("returning cached last modified response", "key", key)

				// return not modified response
				return &http.Response{
					Request:    req,
					StatusCode: http.StatusNotModified,
					Header:     cached.Header,
					Body:       http.NoBody,
				}, nil
			}
		}
	}

	// generate key and check for response
	if cached.BodyKey != "" {
		hkey := crypto.GetHashFromString(cached.BodyKey)
		if reader, err := c.store.Get(context.Background(), "cacher", hkey); err == nil {
			data, readErr := io.ReadAll(reader)
			if readErr == nil {
				slog.Debug("returning cached body response", "key", key)

				// cached response, sending it back
				return &http.Response{
					Request:    req,
					StatusCode: http.StatusOK,
					Header:     cached.Header,
					Body:       io.NopCloser(bytes.NewReader(data)),
				}, nil
			}
		} else if err != cacher.ErrNotFound {
			slog.Warn("failed to get cache", "key", cached.BodyKey)
		}
	}

	// no cache, process the response
	resp, err := c.RoundTripper.RoundTrip(req)
	if err != nil {
		// don't cache errors
		return resp, err
	}

	// don't cache responses with a status code of 4xx or 5xx unless explicit
	if !c.cacheErrors && resp.StatusCode >= 400 {
		return resp, err
	}

	var expires time.Duration
	cacheControlStr := resp.Header.Get(httputil.HeaderCacheControl)
	expiresStr := resp.Header.Get(httputil.HeaderExpires)
	dateStr := resp.Header.Get(httputil.HeaderDate)

	switch {
	case cacheControlStr != "":
		if respDir, err := cacheobject.ParseResponseCacheControl(cacheControlStr); err == nil {
			expires = time.Second * time.Duration(respDir.MaxAge)
		}
	case expiresStr != "" && dateStr != "":
		if d, err := httputil.ParseHTTPDate(dateStr); err == nil {
			if expiresDate, err := httputil.ParseHTTPDate(expiresStr); err == nil {
				expires = expiresDate.Sub(d)
			}
		}
	default:
	}

	if expires > 0 {
		cleanHeader := http.Header{}
		for key, values := range resp.Header {
			if !strings.EqualFold("Set-Cookie", key) {
				cleanHeader[key] = values
			}
		}

		// Get xxhash hasher from pool (much faster than MD5 for cache ETags)
		hasher := xxhashPool.Get().(hash.Hash)
		hasher.Reset()

		// Pre-allocate buffer when content length is known and within cache limit
		var buf *bytes.Buffer
		if resp.ContentLength > 0 && resp.ContentLength < maxCacheSize {
			buf = bytes.NewBuffer(make([]byte, 0, resp.ContentLength))
		} else {
			buf = new(bytes.Buffer)
		}

		// write the cache when the body is closed
		resp.Body = &CacherBody{
			header:     cleanHeader,
			statusCode: resp.StatusCode,
			buff:       buf,
			reader:     resp.Body,
			key:        key,
			expires:    expires,
			store:      c.store,
			hasher:     hasher,
		}
	}

	return resp, err
}

// Deprecated: NewCacher creates a legacy cache transport. Use NewHTTPCacheTransport
// for RFC 7234-compliant HTTP caching with better Vary header support and stale-while-revalidate.
func NewCacher(tr http.RoundTripper, store cacher.Cacher, cacheErrors bool) http.RoundTripper {
	config := DefaultCacheConfig()
	config.CacheErrors = cacheErrors
	return NewHTTPCacheTransport(tr, store, config)
}
