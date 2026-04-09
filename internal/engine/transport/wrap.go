// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"log/slog"
	"net/http"
)

// Wrap performs the wrap operation.
func Wrap(tr http.RoundTripper, fn ModifyResponseFn) RoundTripFn {
	return RoundTripFn(func(req *http.Request) (*http.Response, error) {
		resp, err := tr.RoundTrip(req)
		if err != nil {
			slog.Error("Transport wrap error", "url", req.URL, "error", err)
			return nil, err
		}
		if err = fn(resp); err != nil {
			slog.Error("Transport modify response error", "url", req.URL, "error", err)
			return nil, err
		}
		return resp, nil
	})
}

// WrapError performs the wrap error operation.
func WrapError(tr http.RoundTripper, err error) RoundTripFn {
	return RoundTripFn(func(req *http.Request) (*http.Response, error) {
		resp, err2 := tr.RoundTrip(req)
		if err2 != nil {
			slog.Error("error processing request", "url", req.URL, "error", err2)
			return nil, err
		}
		return resp, nil
	})
}
