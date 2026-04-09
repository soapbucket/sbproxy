// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// Cacher performs the cacher operation.
func Cacher(store cacher.Cacher, ignoreNoCache, storeNon200 bool, minDuration time.Duration, next http.Handler) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		URL := req.URL

		slog.Debug("checking cache", "url", URL.String())

		// Single cache lookup, reused for both conditional checks and serving
		cache, cacheHit := GetCachedResponse(store, URL, req.Context())

		if cacheHit {
			//ETag - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
			noneMatch := req.Header.Get("If-None-Match")
			etag := cache.Headers.Get("ETag")
			if etag != "" && noneMatch != "" && noneMatch == etag {
				slog.Debug("Returning cached etag response", "url", URL.String())
				// return not modified response
				rw.WriteHeader(http.StatusNotModified)
				return
			}

			//Last-Modified - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since
			modifiedSinceStr := req.Header.Get("If-Modified-Since")
			lastModifiedStr := cache.Headers.Get("Last-Modified")
			if modifiedSinceStr != "" && lastModifiedStr != "" {
				if modifiedSince, err := time.Parse(time.RFC1123, modifiedSinceStr); err == nil {
					if lastModified, err := time.Parse(time.RFC1123, lastModifiedStr); err == nil && modifiedSince.After(lastModified) {
						slog.Debug("Returning cached last modified response", "url", URL.String())
						// return not modified response
						rw.WriteHeader(http.StatusNotModified)
						return
					}
				}
			}
		}

		cacheControl, _ := cacheobject.ParseRequestCacheControl(req.Header.Get("Cache-Control"))
		if cacheControl.NoCache && !ignoreNoCache {
			slog.Debug("no-cache response")
			next.ServeHTTP(rw, req)
			return
		}

		// Serve from cache if we have a valid cached response
		if cacheHit {
			slog.Debug("cached response found", "size", cache.Size, "is_too_large", cache.IsTooLarge())
			if cache.IsTooLarge() {
				slog.Debug("partial response, skipping")
				next.ServeHTTP(rw, req)
				return
			}

			for key, value := range cache.Headers {
				rw.Header()[key] = value
			}
			rw.WriteHeader(cache.Status)
			_, _ = rw.Write(cache.Body)
			return
		}

		slog.Debug("no cached response", "url", URL.String())
		cachedRw := NewCachedResponseWriter(rw, MaxCachedResponseSize)

		// Serve the request first, then save to cache
		next.ServeHTTP(cachedRw, req)

		// Save to cache in a goroutine after response is complete
		// Get the cached response data before spawning goroutine to avoid race
		newCache := cachedRw.GetCachedResponse()

		// Release the cached response writer back to the pool
		defer ReleaseCachedResponseWriter(cachedRw)

		go func(cachedData *CachedResponse) {
			if !storeNon200 && cachedData.Status != http.StatusOK {
				slog.Debug("not storing non-200 response", "status", cachedData.Status)
				return
			}

			cc, err := cacheobject.ParseResponseCacheControl(cachedData.Headers.Get("Cache-Control"))
			if err != nil {
				slog.Error("error parsing response cache control", "url", URL.String(), "error", err)
				return
			}

			if cc.PrivatePresent {
				slog.Debug("private response, not caching", "url", URL.String())
				return
			}

			d := time.Duration(cc.MaxAge) * time.Second
			if minDuration > 0 && d < minDuration {
				d = minDuration
			}

			if cc.NoCachePresent && !ignoreNoCache || d == 0 {
				slog.Debug("no-cache response", "url", URL.String(), "duration", d)
				return
			}

			if err := SaveCachedResponse(store, URL, cachedData, d); err != nil {
				slog.Error("error saving cache", "url", URL.String(), "duration", d, "error", err)
			} else {
				slog.Debug("saved response", "url", URL.String(), "duration", d, "size", cachedData.Size)
			}
		}(newCache)
	}
}
