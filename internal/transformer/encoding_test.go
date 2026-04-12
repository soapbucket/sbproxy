package transformer

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"
)

func TestFixEncoding_HeadRequest(t *testing.T) {
	// HEAD responses carry Content-Encoding headers but have no body.
	// fixEncoding must skip decompression to avoid EOF from gz.Reset on empty body.
	body := io.NopCloser(bytes.NewReader(nil))
	req, _ := http.NewRequest(http.MethodHead, "http://example.com", nil)
	resp := &http.Response{
		Request: req,
		Header:  http.Header{"Content-Encoding": []string{"gzip"}},
		Body:    body,
	}

	err := fixEncoding(resp)
	if err != nil {
		t.Fatalf("expected no error for HEAD request, got: %v", err)
	}

	// Content-Encoding should still be present (early return skips header deletion)
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("expected Content-Encoding to remain for HEAD, got %q",
			resp.Header.Get("Content-Encoding"))
	}
}

func TestFixEncoding_Gzip(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	original := "hello world"
	gz.Write([]byte(original))
	gz.Close()

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp := &http.Response{
		Request: req,
		Header:  http.Header{"Content-Encoding": []string{"gzip"}},
		Body:    io.NopCloser(&buf),
	}

	err := fixEncoding(resp)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(result) != original {
		t.Errorf("expected %q, got %q", original, string(result))
	}

	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("expected Content-Encoding to be removed, got %q", ce)
	}
}

func TestFixEncoding_NoEncoding(t *testing.T) {
	original := "plain text body"
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp := &http.Response{
		Request: req,
		Header:  http.Header{},
		Body:    io.NopCloser(bytes.NewBufferString(original)),
	}

	err := fixEncoding(resp)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	if string(result) != original {
		t.Errorf("expected %q, got %q", original, string(result))
	}
}
