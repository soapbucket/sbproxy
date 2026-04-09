// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import "net/http"

// Beacon performs the beacon operation.
func Beacon(fn ModifyResponseFn) http.RoundTripper {
	return Wrap(Null, func(resp *http.Response) error {
		return fn(resp)
	})
}
