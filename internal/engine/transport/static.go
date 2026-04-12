// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"io"
	"net/http"
)

// Static performs the static operation.
func Static(body io.ReadCloser, contentType string) RoundTripFn {
	return Wrap(Null, func(resp *http.Response) error {
		resp.Body = body
		resp.Header.Set("Content-Type", contentType)

		return nil
	})

}
