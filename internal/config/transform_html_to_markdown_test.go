package config

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func TestHTMLToMarkdownTransform_LoadConfig(t *testing.T) {
	data := []byte(`{
		"type": "html_to_markdown",
		"token_counting": true,
		"accept_header_negotiation": true
	}`)

	cfg, err := NewHTMLToMarkdownTransform(data)
	if err != nil {
		t.Fatalf("NewHTMLToMarkdownTransform failed: %v", err)
	}

	if cfg.GetType() != TransformHTMLToMarkdown {
		t.Errorf("GetType() = %q, want %q", cfg.GetType(), TransformHTMLToMarkdown)
	}

	htmlCfg, ok := cfg.(*HTMLToMarkdownTransformConfig)
	if !ok {
		t.Fatalf("Config is not HTMLToMarkdownTransformConfig")
	}

	if !htmlCfg.TokenCounting {
		t.Error("TokenCounting not set correctly")
	}

	if !htmlCfg.AcceptHeaderNegotiation {
		t.Error("AcceptHeaderNegotiation not set correctly")
	}
}

func TestHTMLToMarkdownTransform_Apply(t *testing.T) {
	html := `<html>
	<body>
		<h1>Test Title</h1>
		<p>This is a test paragraph.</p>
	</body>
	</html>`

	cfg := &HTMLToMarkdownTransformConfig{
		BaseTransform: BaseTransform{
			TransformType:           TransformHTMLToMarkdown,
			disabledByContentType:   make(map[string]bool),
		},
		TokenCounting:           true,
		AcceptHeaderNegotiation: true,
	}

	// Initialize the transform
	cfg.tr = transformer.ConvertMarkdown(transformer.MarkdownOptions{
		TokenCounting:           true,
		AcceptHeaderNegotiation: true,
		TokenEstimate:           1.3,
	})

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(html))),
		Request: &http.Request{
			Method: http.MethodGet,
			Header: http.Header{
				"Accept": []string{"text/markdown"},
			},
		},
	}

	err := cfg.Apply(resp)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Read response body
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify markdown conversion
	if !strings.Contains(bodyStr, "#") {
		t.Error("Expected heading marker (#) in markdown output")
	}

	// Check Content-Type header
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/markdown") {
		t.Errorf("Expected Content-Type to contain markdown, got: %s", contentType)
	}

	// Check token count header
	tokenCount := resp.Header.Get("x-markdown-tokens")
	if tokenCount == "" {
		t.Error("Expected x-markdown-tokens header")
	}
}

func TestHTMLToMarkdownTransform_DisabledByConfig(t *testing.T) {
	html := `<html><body><h1>Test</h1></body></html>`

	cfg := &HTMLToMarkdownTransformConfig{
		BaseTransform: BaseTransform{
			TransformType:           TransformHTMLToMarkdown,
			disabledByContentType:   make(map[string]bool),
			Disabled:                true,
		},
	}

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(html))),
	}

	err := cfg.Apply(resp)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Content-Type should remain HTML since transform is disabled
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type to remain text/html when disabled")
	}
}

func TestHTMLToMarkdownTransform_DefaultOptions(t *testing.T) {
	data := []byte(`{
		"type": "html_to_markdown"
	}`)

	cfg, err := NewHTMLToMarkdownTransform(data)
	if err != nil {
		t.Fatalf("NewHTMLToMarkdownTransform failed: %v", err)
	}

	htmlCfg := cfg.(*HTMLToMarkdownTransformConfig)

	// Verify defaults
	if !htmlCfg.AcceptHeaderNegotiation {
		t.Error("AcceptHeaderNegotiation should default to true")
	}

	if htmlCfg.TokenEstimate != 1.3 {
		t.Errorf("TokenEstimate = %v, want 1.3", htmlCfg.TokenEstimate)
	}

	if htmlCfg.TokenCounting {
		t.Error("TokenCounting should default to false")
	}
}
