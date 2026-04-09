// Package requestdata builds and propagates per-request metadata through the proxy pipeline.
package requestdata

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// RequestDataMiddleware returns HTTP middleware for request data.
func RequestDataMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()

		var maxDepth int
		if m := manager.GetManager(ctx); m != nil {
			maxDepth = m.GetGlobalSettings().MaxRecursionDepth
		} else {
			slog.Warn("manager not found")
		}
		if maxDepth == 0 {
			maxDepth = DefaultMaxDepth
		}

		var id string
		var level int
		var err error

		if r.Header.Get(httputil.HeaderXSbRequestID) != "" {
			id, level, err = ParseRequestID(r.Header.Get(httputil.HeaderXSbRequestID))
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
			slog.Error("max depth exceeded", "error", ErrMaxDepthExceeded, "request_id", id)
			httputil.HandleError(http.StatusLoopDetected, ErrMaxDepthExceeded, w, r)
			return
		}
		requestData := reqctx.NewRequestData()
		requestData.ID = id
		requestData.Depth = level
		defer requestData.Release()

		// Set the request ID header using stack buffer to avoid fmt.Sprintf allocation
		var buf [64]byte
		n := copy(buf[:], requestData.ID)
		buf[n] = ':'
		n++
		n += len(strconv.AppendInt(buf[n:n], int64(requestData.Depth), 10))
		headerValue := string(buf[:n])
		r.Header.Set(httputil.HeaderXSbRequestID, headerValue)
		requestData.AddDebugHeader(httputil.HeaderXSbRequestID, headerValue)

		ctx = reqctx.SetRequestData(ctx, requestData)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
