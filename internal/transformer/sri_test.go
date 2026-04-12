package transformer

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSRITransform(t *testing.T) {
	tests := []struct {
		name         string
		algorithm    string
		contentTypes []string
		addHeader    bool
		addToHTML    bool
		cacheHashes  bool
		wantErr      bool
	}{
		{"default", "", nil, true, false, false, false},
		{"sha256", "sha256", []string{"application/javascript"}, true, false, true, false},
		{"sha384", "sha384", []string{"text/css"}, true, false, false, false},
		{"sha512", "sha512", []string{"application/json"}, false, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transform, err := NewSRITransform(tt.algorithm, tt.contentTypes, tt.addHeader, tt.addToHTML, tt.cacheHashes)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSRITransform() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && transform == nil {
				t.Error("NewSRITransform() returned nil transform")
			}
		})
	}
}

func TestSRITransform_Modify(t *testing.T) {
	transform, err := NewSRITransform("sha256", []string{"application/javascript"}, true, false, false)
	if err != nil {
		t.Fatalf("NewSRITransform() error = %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/script.js", nil)
	body := []byte("console.log('test');")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/javascript")
	resp.Body = http.NoBody

	// Create a proper body reader
	resp.Body = http.NoBody
	resp.ContentLength = int64(len(body))

	// Modify response
	err = transform.Modify(resp)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	// Check if integrity header was added
	integrity := resp.Header.Get("Integrity")
	if integrity == "" {
		t.Error("Integrity header should be set")
	}

	// Check format (should be sha256-<base64>)
	if !strings.HasPrefix(integrity, "sha256-") {
		t.Errorf("Integrity header should start with 'sha256-', got %v", integrity)
	}
}

func TestSRITransform_Modify_UnsupportedContentType(t *testing.T) {
	transform, err := NewSRITransform("sha384", []string{"application/javascript"}, true, false, false)
	if err != nil {
		t.Fatalf("NewSRITransform() error = %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/image.png", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
	resp.Header.Set("Content-Type", "image/png")

	err = transform.Modify(resp)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	// Integrity header should not be set for unsupported content types
	integrity := resp.Header.Get("Integrity")
	if integrity != "" {
		t.Errorf("Integrity header should not be set for image/png, got %v", integrity)
	}
}

func TestSRITransform_CacheHashes(t *testing.T) {
	transform, err := NewSRITransform("sha256", []string{"application/javascript"}, true, false, true)
	if err != nil {
		t.Fatalf("NewSRITransform() error = %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/script.js", nil)
	body := []byte("console.log('test');")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/javascript")
	resp.ContentLength = int64(len(body))

	// First call - should generate hash
	err = transform.Modify(resp)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	integrity1 := resp.Header.Get("Integrity")

	// Second call with same URL - should use cache
	resp2 := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
	resp2.Header.Set("Content-Type", "application/javascript")
	resp2.ContentLength = int64(len(body))

	err = transform.Modify(resp2)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	integrity2 := resp2.Header.Get("Integrity")

	if integrity1 != integrity2 {
		t.Errorf("Cached hash should match, got %v and %v", integrity1, integrity2)
	}
}

func TestNewSRITransformFromConfig(t *testing.T) {
	cfg := SRITransformConfig{
		Algorithm:          "sha384",
		ContentTypes:       []string{"text/css"},
		AddIntegrityHeader: true,
		CacheHashes:        true,
	}

	transform, err := NewSRITransformFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewSRITransformFromConfig() error = %v", err)
	}

	if transform == nil {
		t.Error("NewSRITransformFromConfig() returned nil transform")
	}
}
