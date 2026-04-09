package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockRedirectTransport simulates a server that redirects
type mockRedirectTransport struct {
	redirectCount  int
	maxRedirects   int
	finalStatus    int
	redirectTarget string
}

func (m *mockRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.redirectCount < m.maxRedirects {
		m.redirectCount++
		resp := &http.Response{
			StatusCode: http.StatusFound,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}
		resp.Header.Set("Location", m.redirectTarget)
		return resp, nil
	}

	// Final response
	return &http.Response{
		StatusCode: m.finalStatus,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func TestNewRedirecterSingleRedirect(t *testing.T) {
	mockTr := &mockRedirectTransport{
		maxRedirects:   1,
		finalStatus:    http.StatusOK,
		redirectTarget: "http://example.com/redirected",
	}

	redirecter := NewRedirecter(mockTr, 10)

	req := httptest.NewRequest("GET", "http://example.com/original", nil)
	resp, err := redirecter.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected final status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if mockTr.redirectCount != 1 {
		t.Errorf("expected 1 redirect, got %d", mockTr.redirectCount)
	}
}

func TestNewRedirecterMultipleRedirects(t *testing.T) {
	mockTr := &mockRedirectTransport{
		maxRedirects:   3,
		finalStatus:    http.StatusOK,
		redirectTarget: "http://example.com/redirected",
	}

	redirecter := NewRedirecter(mockTr, 10)

	req := httptest.NewRequest("GET", "http://example.com/original", nil)
	resp, err := redirecter.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected final status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if mockTr.redirectCount != 3 {
		t.Errorf("expected 3 redirects, got %d", mockTr.redirectCount)
	}
}

func TestNewRedirecterNoRedirect(t *testing.T) {
	mockTr := &mockRedirectTransport{
		maxRedirects: 0,
		finalStatus:  http.StatusOK,
	}

	redirecter := NewRedirecter(mockTr, 10)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	resp, err := redirecter.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if mockTr.redirectCount != 0 {
		t.Errorf("expected no redirects, got %d", mockTr.redirectCount)
	}
}

type funcTransport func(*http.Request) (*http.Response, error)

func (f funcTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewRedirecterMovedPermanently(t *testing.T) {
	callCount := 0
	mockTr := funcTransport(func(req *http.Request) (*http.Response, error) {
		callCount++
		if callCount == 1 {
			resp := &http.Response{
				StatusCode: http.StatusMovedPermanently,
				Header:     make(http.Header),
				Body:       http.NoBody,
				Request:    req,
			}
			resp.Header.Set("Location", "http://example.com/new-location")
			return resp, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})

	redirecter := NewRedirecter(mockTr, 10)

	req := httptest.NewRequest("GET", "http://example.com/old", nil)
	resp, err := redirecter.RoundTrip(req)

	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected final status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if callCount != 2 {
		t.Errorf("expected 2 calls (1 redirect + 1 final), got %d", callCount)
	}
}

func TestNewRedirecterInvalidLocation(t *testing.T) {
	mockTr := funcTransport(func(req *http.Request) (*http.Response, error) {
		resp := &http.Response{
			StatusCode: http.StatusFound,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}
		// Invalid URL
		resp.Header.Set("Location", "://invalid-url")
		return resp, nil
	})

	redirecter := NewRedirecter(mockTr, 10)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	_, err := redirecter.RoundTrip(req)

	if err == nil {
		t.Error("expected error for invalid redirect location")
	}
}

func TestNewRedirecterOtherStatusCodes(t *testing.T) {
	statuses := []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusAccepted,
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusTemporaryRedirect, // 307 - not handled
		http.StatusPermanentRedirect, // 308 - not handled
	}

	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			mockTr := funcTransport(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       http.NoBody,
					Request:    req,
				}, nil
			})

			redirecter := NewRedirecter(mockTr, 10)

			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			resp, err := redirecter.RoundTrip(req)

			if err != nil {
				t.Fatalf("RoundTrip returned error: %v", err)
			}

			if resp.StatusCode != status {
				t.Errorf("expected status %d, got %d", status, resp.StatusCode)
			}
		})
	}
}

// Benchmark tests

func BenchmarkRedirecter(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockRedirectTransport{
		maxRedirects:   1,
		finalStatus:    http.StatusOK,
		redirectTarget: "http://example.com/redirected",
	}

	redirecter := NewRedirecter(mockTr, 10)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mockTr.redirectCount = 0 // Reset for each iteration
		redirecter.RoundTrip(req)
	}
}

func BenchmarkRedirecterNoRedirect(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockRedirectTransport{
		maxRedirects: 0,
		finalStatus:  http.StatusOK,
	}

	redirecter := NewRedirecter(mockTr, 10)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		redirecter.RoundTrip(req)
	}
}

func BenchmarkRedirecterMultiple(b *testing.B) {
	b.ReportAllocs()
	mockTr := &mockRedirectTransport{
		maxRedirects:   5,
		finalStatus:    http.StatusOK,
		redirectTarget: "http://example.com/redirected",
	}

	redirecter := NewRedirecter(mockTr, 10)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mockTr.redirectCount = 0
		redirecter.RoundTrip(req)
	}
}
