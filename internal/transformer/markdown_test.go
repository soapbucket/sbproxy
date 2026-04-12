package transformer

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestConvertMarkdown_BasicHTML(t *testing.T) {
	html := `<html>
	<body>
		<h1>Hello World</h1>
		<p>This is a paragraph.</p>
	</body>
	</html>`

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

	opts := DefaultMarkdownOptions()
	err := convertMarkdown(resp, opts)

	if err != nil {
		t.Fatalf("convertMarkdown failed: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check that markdown contains expected elements
	if !strings.Contains(bodyStr, "#") {
		t.Error("Expected heading marker (#) in markdown output")
	}

	// Check Content-Type header
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/markdown") {
		t.Errorf("Expected Content-Type to be markdown, got: %s", contentType)
	}

	t.Logf("Output markdown:\n%s", bodyStr)
}

func TestConvertMarkdown_SkipsNonHTML(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"test": "data"}`))),
		Request: &http.Request{
			Method: http.MethodGet,
			Header: http.Header{
				"Accept": []string{"text/markdown"},
			},
		},
	}

	opts := DefaultMarkdownOptions()
	err := convertMarkdown(resp, opts)

	if err != nil {
		t.Fatalf("convertMarkdown failed: %v", err)
	}

	// Content-Type should remain unchanged
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type to remain application/json, got: %s", contentType)
	}
}

func TestConvertMarkdown_SkipsWithoutAcceptHeader(t *testing.T) {
	html := `<html><body><h1>Test</h1></body></html>`

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(html))),
		Request: &http.Request{
			Method: http.MethodGet,
			Header: http.Header{}, // No Accept header
		},
	}

	opts := DefaultMarkdownOptions()
	opts.AcceptHeaderNegotiation = true
	err := convertMarkdown(resp, opts)

	if err != nil {
		t.Fatalf("convertMarkdown failed: %v", err)
	}

	// Content-Type should remain HTML
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type to remain text/html, got: %s", contentType)
	}
}

func TestConvertMarkdown_SkipsHEADMethod(t *testing.T) {
	html := `<html><body><h1>Test</h1></body></html>`

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(html))),
		Request: &http.Request{
			Method: http.MethodHead,
			Header: http.Header{
				"Accept": []string{"text/markdown"},
			},
		},
	}

	opts := DefaultMarkdownOptions()
	err := convertMarkdown(resp, opts)

	if err != nil {
		t.Fatalf("convertMarkdown failed: %v", err)
	}

	// Content-Type should remain HTML
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type to remain text/html for HEAD request, got: %s", contentType)
	}
}

func TestConvertMarkdown_TokenCounting(t *testing.T) {
	html := `<html>
	<body>
		<h1>Hello World</h1>
		<p>This is a test paragraph with several words in it.</p>
	</body>
	</html>`

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

	opts := DefaultMarkdownOptions()
	opts.TokenCounting = true
	err := convertMarkdown(resp, opts)

	if err != nil {
		t.Fatalf("convertMarkdown failed: %v", err)
	}

	// Check token count header
	tokenCountStr := resp.Header.Get(TokenCountHeader)
	if tokenCountStr == "" {
		t.Error("Expected x-markdown-tokens header in response")
	} else {
		t.Logf("Token count: %s", tokenCountStr)
	}
}

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		text              string
		tokensPerWord     float64
		expectedMinTokens int
		expectedMaxTokens int
	}{
		{
			text:              "Hello world",
			tokensPerWord:     1.0,
			expectedMinTokens: 2,
			expectedMaxTokens: 2,
		},
		{
			text:              "Hello world",
			tokensPerWord:     1.3,
			expectedMinTokens: 2,
			expectedMaxTokens: 3,
		},
		{
			text:              "",
			tokensPerWord:     1.3,
			expectedMinTokens: 0,
			expectedMaxTokens: 0,
		},
		{
			text:              "This is a longer sentence with many words for testing token estimation.",
			tokensPerWord:     1.3,
			expectedMinTokens: 10,
			expectedMaxTokens: 20,
		},
	}

	for _, tt := range tests {
		tokens := estimateTokens(tt.text, tt.tokensPerWord)
		if tokens < tt.expectedMinTokens || tokens > tt.expectedMaxTokens {
			t.Errorf("estimateTokens(%q, %v) = %d, want between %d and %d",
				tt.text, tt.tokensPerWord, tokens, tt.expectedMinTokens, tt.expectedMaxTokens)
		}
	}
}

func TestExtractBodyMarkdown_ComplexMarkdown(t *testing.T) {
	htmlStr := `
	<html>
	<body>
		<h1>Main Title</h1>
		<p>Introduction paragraph with <strong>bold</strong> and <em>italic</em> text.</p>
		<h2>Section 2</h2>
		<p>More content here.</p>
		<ul>
			<li>First item</li>
			<li>Second item</li>
		</ul>
		<blockquote>A quote</blockquote>
		<pre><code>code block</code></pre>
		<a href="http://example.com">Link text</a>
		<img src="image.png" alt="An image" />
		<script>alert("ignored");</script>
	</body>
	</html>`

	doc, err := html.Parse(bytes.NewReader([]byte(htmlStr)))
	if err != nil {
		t.Fatalf("html.Parse failed: %v", err)
	}

	result := string(extractBodyMarkdown(doc))
	t.Logf("Extracted HTML:\n%s", result)

	// Verify key elements are present
	checks := map[string]bool{
		"Main Title": strings.Contains(result, "Main Title"),
		"bold":       strings.Contains(result, "bold"),
		"italic":     strings.Contains(result, "italic"),
		"First item": strings.Contains(result, "First item"),
		"Quote":      strings.Contains(result, "quote"),
		"Link":       strings.Contains(result, "Link text"),
		"Image":      strings.Contains(result, "image.png"),
		"No script":  !strings.Contains(result, "alert"),
	}

	for name, passed := range checks {
		if !passed {
			t.Errorf("Check failed: %s", name)
		}
	}
}
