// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"log/slog"
	"net/http"
	"time"
)

// SyntheticDelay introduces an artificial delay before invoking fn.
// It does not enforce a timeout on actual requests.
func SyntheticDelay(d time.Duration, fn ModifyResponseFn) RoundTripFn {
	return Wrap(Null, func(resp *http.Response) error {
		slog.Debug("synthetic delay request", "url", resp.Request.URL, "delay", d)
		time.Sleep(d)
		return fn(resp)
	})

}
