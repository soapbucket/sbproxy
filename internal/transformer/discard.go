// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bufio"
	"io"
	"net/http"
)

// Discard performs the discard operation.
func Discard(n int) Transformer {
	return Func(func(resp *http.Response) error {
		return discard(resp, n)
	})
}

// Discard reads ahead by n bytes and discards them.
func discard(resp *http.Response, n int) error {

	if n <= 0 {
		// If n is 0 or negative, do nothing
		return nil
	}

	// skip ahead
	reader := bufio.NewReader(resp.Body)
	if _, err := reader.Discard(n); err != nil {
		// If we can't discard n bytes (e.g., body is smaller), that's ok
		// Just read what's available
		if err != io.EOF {
			return err
		}
	}

	// reset the body
	resp.Body = NewTransformReader(reader, resp.Body)

	return nil
}
