// error_pages.go implements custom error page lookup and rendering for HTTP error responses.
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

// FindErrorPage finds the appropriate error page for a given status code.
// Priority: specific status codes first, then fallback to a catch-all page
// (one with no status codes specified).
func (ep ErrorPages) FindErrorPage(statusCode int) (*ErrorPage, bool) {
	for i := range ep {
		if len(ep[i].Status) > 0 && slices.Contains(ep[i].Status, statusCode) {
			return &ep[i], true
		}
	}
	for i := range ep {
		if len(ep[i].Status) == 0 {
			return &ep[i], true
		}
	}
	return nil, false
}

// SelectErrorPage picks the best error page for the request's Accept header.
// It first filters pages by status code, then selects the page whose ContentType
// best matches the client's Accept header. If no content type match is found,
// the first status-matching page is returned.
func SelectErrorPage(pages []ErrorPage, statusCode int, acceptHeader string) *ErrorPage {
	if len(pages) == 0 {
		return nil
	}

	// Collect pages that match the status code.
	var candidates []*ErrorPage
	var catchAll []*ErrorPage
	for i := range pages {
		if len(pages[i].Status) > 0 && slices.Contains(pages[i].Status, statusCode) {
			candidates = append(candidates, &pages[i])
		} else if len(pages[i].Status) == 0 {
			catchAll = append(catchAll, &pages[i])
		}
	}

	// Fall back to catch-all pages if no specific match.
	if len(candidates) == 0 {
		candidates = catchAll
	}
	if len(candidates) == 0 {
		return nil
	}

	// If no Accept header, return the first candidate.
	if acceptHeader == "" {
		return candidates[0]
	}

	// Build a list of available content types from candidates.
	available := make([]string, len(candidates))
	for i, c := range candidates {
		ct := c.ContentType
		if ct == "" {
			ct = "text/html"
		}
		available[i] = ct
	}

	// Parse Accept header and find the best match.
	// Simple inline negotiation (does not import httpkit to avoid circular deps).
	bestIdx := 0
	bestQ := -1.0
	for _, part := range splitAccept(acceptHeader) {
		mt, q := parseMediaType(part)
		if q <= bestQ {
			continue
		}
		for i, avail := range available {
			if acceptMatches(mt, avail) && q > bestQ {
				bestQ = q
				bestIdx = i
			}
		}
	}

	return candidates[bestIdx]
}

// splitAccept splits an Accept header value by commas.
func splitAccept(header string) []string {
	var parts []string
	for _, p := range strings.Split(header, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// parseMediaType extracts the media type and quality from a single Accept entry.
func parseMediaType(entry string) (string, float64) {
	parts := strings.Split(entry, ";")
	mt := strings.TrimSpace(parts[0])
	q := 1.0
	for _, param := range parts[1:] {
		param = strings.TrimSpace(param)
		if strings.HasPrefix(param, "q=") || strings.HasPrefix(param, "Q=") {
			if v, err := strconv.ParseFloat(param[2:], 64); err == nil && v >= 0 && v <= 1 {
				q = v
			}
		}
	}
	return mt, q
}

// acceptMatches checks whether a media type pattern matches a concrete type.
func acceptMatches(pattern, concrete string) bool {
	if pattern == "*/*" {
		return true
	}
	pParts := strings.SplitN(pattern, "/", 2)
	cParts := strings.SplitN(concrete, "/", 2)
	if len(pParts) != 2 || len(cParts) != 2 {
		return pattern == concrete
	}
	if pParts[0] != cParts[0] && pParts[0] != "*" {
		return false
	}
	if pParts[1] != cParts[1] && pParts[1] != "*" {
		return false
	}
	return true
}

// wrapErrorPages wraps the handler with custom error page interception.
// When the inner handler writes a status >= 400 and a matching ErrorPage is
// configured, the custom page body is served instead of the original response.
// This is the OUTERMOST wrapper in the compiled handler chain so that error
// pages apply regardless of which inner layer produced the error.
func wrapErrorPages(next http.Handler, cfg json.RawMessage) http.Handler {
	if isNullOrEmpty(cfg) {
		return next
	}
	var pages ErrorPages
	if err := json.Unmarshal(cfg, &pages); err != nil {
		slog.Warn("compile: invalid error_pages config, skipping", "error", err)
		return next
	}
	if len(pages) == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		epw := &errorPageResponseWriter{
			underlying: w,
			header:     make(http.Header),
			pages:      pages,
			request:    r,
		}
		next.ServeHTTP(epw, r)
		epw.flush()
	})
}

// errorPageResponseWriter wraps the real http.ResponseWriter to intercept error
// responses. It buffers the entire response body so that if a 4xx/5xx status is
// detected, it can discard the original body and substitute the custom error page.
// This buffering approach is necessary because HTTP headers and status must be
// sent before the body, but we need to see the status before deciding whether
// to intercept.
type errorPageResponseWriter struct {
	underlying  http.ResponseWriter
	header      http.Header
	pages       ErrorPages
	request     *http.Request
	statusCode  int
	intercepted bool // true when we are serving a custom error page
	flushed     bool // true after flush() has been called
	wroteHeader bool
	body        []byte // buffered body from inner handler (discarded if intercepted)
}

func (w *errorPageResponseWriter) Header() http.Header {
	return w.header
}

func (w *errorPageResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = code

	if code >= 400 {
		if page, ok := w.pages.FindErrorPage(code); ok {
			w.intercepted = true
			w.serveErrorPage(page, code)
			return
		}
	}
}

func (w *errorPageResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.intercepted {
		// Discard the original body; custom page was already served.
		return len(b), nil
	}
	// Buffer the body until flush().
	w.body = append(w.body, b...)
	return len(b), nil
}

// Flush supports streaming if the underlying writer implements http.Flusher.
func (w *errorPageResponseWriter) Flush() {
	if f, ok := w.underlying.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack supports WebSocket upgrades if the underlying writer supports it.
func (w *errorPageResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.underlying.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}

// flush writes the final response to the underlying ResponseWriter. If the
// response was intercepted, this is a no-op (the custom page was already written
// in serveErrorPage).
func (w *errorPageResponseWriter) flush() {
	if w.flushed {
		return
	}
	w.flushed = true

	if w.intercepted {
		return
	}

	// No interception: copy buffered headers, status, and body to the real writer.
	dst := w.underlying.Header()
	for k, vs := range w.header {
		dst[k] = vs
	}

	code := w.statusCode
	if code == 0 {
		code = http.StatusOK
	}
	w.underlying.WriteHeader(code)

	if len(w.body) > 0 {
		_, _ = w.underlying.Write(w.body)
	}
}

// serveErrorPage renders and writes the custom error page to the underlying
// ResponseWriter.
func (w *errorPageResponseWriter) serveErrorPage(page *ErrorPage, statusCode int) {
	body := page.Body

	// If template rendering is enabled, resolve Mustache variables.
	if page.Template && body != "" {
		ctx := map[string]any{
			"status_code": statusCode,
			"error":       http.StatusText(statusCode),
			"request": map[string]any{
				"path":   w.request.URL.Path,
				"method": w.request.Method,
			},
		}
		rendered, err := templateresolver.ResolveWithContext(body, ctx)
		if err != nil {
			slog.Warn("error_pages: template rendering failed, using raw body", "error", err)
		} else {
			body = rendered
		}
	}

	// Determine content type.
	contentType := page.ContentType
	if contentType == "" {
		contentType = "text/html"
	}

	// Use the page's status_code override if set.
	respCode := statusCode
	if page.StatusCode > 0 {
		respCode = page.StatusCode
	}

	// Copy any extra headers from the page config.
	dst := w.underlying.Header()
	for k, v := range page.Headers {
		dst.Set(k, v)
	}
	dst.Set("Content-Type", contentType)
	dst.Set("Content-Length", strconv.Itoa(len(body)))

	w.underlying.WriteHeader(respCode)
	_, _ = w.underlying.Write([]byte(body))
}
