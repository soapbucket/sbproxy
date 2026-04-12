// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/request/data"
)

const (
	// MaxBodyCaptureSize is the maximum body size we will buffer for capture (1MB)
	MaxBodyCaptureSize = 1024 * 1024
)

// FastPathMiddleware combines RequestData initialization and OriginalRequest capture
// into a single middleware to reduce context overhead and redundant work.
func FastPathMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// 1. Get Manager and MaxDepth
		var maxDepth int
		if m := manager.GetManager(ctx); m != nil {
			maxDepth = m.GetGlobalSettings().MaxRecursionDepth
		}
		if maxDepth == 0 {
			maxDepth = requestdata.DefaultMaxDepth
		}

		// 2. Parse or Generate Request ID
		var id string
		var level int
		var err error

		if rid := r.Header.Get(httputil.HeaderXSbRequestID); rid != "" {
			id, level, err = requestdata.ParseRequestID(rid)
			if err != nil {
				slog.Error("error parsing request ID", "error", err)
				httputil.HandleError(http.StatusBadRequest, err, w, r)
				return
			}
			level++
		} else {
			id = uuid.NewString()
			level = 1
		}

		if level > maxDepth {
			slog.Error("max depth exceeded", "error", requestdata.ErrMaxDepthExceeded, "request_id", id)
			httputil.HandleError(http.StatusLoopDetected, requestdata.ErrMaxDepthExceeded, w, r)
			return
		}

		// 3. Initialize RequestData from Pool
		rd := reqctx.NewRequestData()
		rd.ID = id
		rd.Depth = level
		defer rd.Release()

		// 4. Set Request ID Header (optimized)
		var buf [64]byte
		n := copy(buf[:], rd.ID)
		buf[n] = ':'
		n++
		n += len(strconv.AppendInt(buf[n:n], int64(rd.Depth), 10))
		headerValue := string(buf[:n])
		r.Header.Set(httputil.HeaderXSbRequestID, headerValue)
		rd.AddDebugHeader(httputil.HeaderXSbRequestID, headerValue)

		// 5. Capture Original Request metadata and lazily mirror the body as it is read.
		// Headers and URL are deferred to first access (sync.Once) to avoid allocations
		// on simple proxy-through requests that never inspect request metadata.
		contentType := r.Header.Get("Content-Type")
		isJSON := strings.Contains(strings.ToLower(contentType), "application/json")

		orig := reqctx.OriginalRequestDataPool.Get().(*reqctx.OriginalRequestData)
		orig.Method = r.Method
		orig.Path = r.URL.Path
		orig.RawQuery = r.URL.RawQuery
		orig.Body = nil
		orig.IsJSON = isJSON
		orig.ContentType = contentType
		orig.RemoteAddr = r.RemoteAddr
		orig.SetRequest(r) // store ref for lazy Headers/URL computation
		rd.OriginalRequest = orig

		// Capture body when present and Content-Length is positive (known) or -1 (unknown/chunked).
		// Reject negative values other than -1 to avoid allocating buffers with nonsensical sizes.
		if r.Body != nil && (r.ContentLength == -1 || (r.ContentLength > 0 && r.ContentLength <= MaxBodyCaptureSize)) {
			// Pre-allocate body buffer from Content-Length when known to avoid reallocation
			if r.ContentLength > 0 {
				orig.Body = make([]byte, 0, r.ContentLength)
			}
			r.Body = newOriginalRequestBodyCapture(r.Body, orig, MaxBodyCaptureSize)
		}

		// 6. Update Context and Call Next
		ctx = reqctx.SetRequestData(ctx, rd)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

type originalRequestBodyCapture struct {
	body      io.ReadCloser
	target    *reqctx.OriginalRequestData
	remaining int64
}

func newOriginalRequestBodyCapture(body io.ReadCloser, target *reqctx.OriginalRequestData, limit int64) io.ReadCloser {
	return &originalRequestBodyCapture{
		body:      body,
		target:    target,
		remaining: limit,
	}
}

func (c *originalRequestBodyCapture) Read(p []byte) (int, error) {
	n, err := c.body.Read(p)
	if n > 0 && c.target != nil && c.remaining > 0 {
		captureN := n
		if int64(captureN) > c.remaining {
			captureN = int(c.remaining)
		}
		c.target.Body = append(c.target.Body, p[:captureN]...)
		c.remaining -= int64(captureN)
	}
	return n, err
}

func (c *originalRequestBodyCapture) Close() error {
	return c.body.Close()
}
