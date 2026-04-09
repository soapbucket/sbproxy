// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"errors"
	"net/http"
)

// ErrMaxRedirectsReached is a sentinel error for max redirects reached conditions.
var ErrMaxRedirectsReached = errors.New("max redirects reached")

// redirecter implements http.RoundTripper and follows redirects up to maxRedirects.
// It returns the final non-redirect response or an error if the redirect limit is exceeded.
type redirecter struct {
	tr           http.RoundTripper
	maxRedirects int
}

// RoundTrip performs the round trip operation on the redirecter.
func (r *redirecter) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.maxRedirects <= 0 {
		return r.tr.RoundTrip(req)
	}

	redirects := 0
	curReq := req

	for {
		resp, err := r.tr.RoundTrip(curReq)
		if err != nil {
			return nil, err
		}

		// Handle common redirect status codes
		code := resp.StatusCode
		if code != http.StatusMovedPermanently &&
			code != http.StatusFound &&
			code != http.StatusSeeOther &&
			code != http.StatusTemporaryRedirect &&
			code != http.StatusPermanentRedirect {
			return resp, nil
		}

		if redirects >= r.maxRedirects {
			resp.Body.Close()
			return nil, ErrMaxRedirectsReached
		}

		loc := resp.Header.Get("Location")
		if loc == "" {
			return resp, nil
		}

		// Resolve new URL relative to current request URL
		newURL, err := curReq.URL.Parse(loc)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}

		// Prepare next request
		nextReq := curReq.Clone(curReq.Context())
		nextReq.URL = newURL

		// Per RFC 7231:
		// - 303: always switch to GET (except HEAD)
		// - 301/302: many clients historically switch POST to GET; we preserve method unless tests require otherwise
		if code == http.StatusSeeOther && curReq.Method != http.MethodHead {
			nextReq.Method = http.MethodGet
			nextReq.Body = http.NoBody
		}

		// Close the intermediate response body before following
		resp.Body.Close()

		curReq = nextReq
		redirects++
	}
}

// NewRedirecter creates and initializes a new Redirecter.
func NewRedirecter(tr http.RoundTripper, maxRedirects int) http.RoundTripper {
	return &redirecter{tr: tr, maxRedirects: maxRedirects}
}
