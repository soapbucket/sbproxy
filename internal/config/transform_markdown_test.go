package config

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMarkdownTransform_Basic(t *testing.T) {
	markdown := `# Hello World

This is a **bold** and *italic* text.

## Features

- Item 1
- Item 2
- Item 3

[Link](https://example.com)
`

	config := &MarkdownTransform{
		DisableTables:         false,
		DisableFencedCode:     false,
		DisableAutolink:       false,
		DisableStrikethrough:  false,
		DisableAutoHeadingIDs: false,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(markdown)),
	}
	resp.Header.Set("Content-Type", "text/markdown")

	err := config.tr.Modify(resp)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	html := string(body)

	// Check for expected HTML elements
	if !strings.Contains(html, "<h1") {
		t.Error("Expected <h1> tag for # heading")
	}
	if !strings.Contains(html, "<h2") {
		t.Error("Expected <h2> tag for ## heading")
	}
	if !strings.Contains(html, "<strong>") {
		t.Error("Expected <strong> tag for **bold**")
	}
	if !strings.Contains(html, "<em>") {
		t.Error("Expected <em> tag for *italic*")
	}
	if !strings.Contains(html, "<ul>") {
		t.Error("Expected <ul> tag for list")
	}
	if !strings.Contains(html, "<li>") {
		t.Error("Expected <li> tag for list items")
	}
	if !strings.Contains(html, "<a href=\"https://example.com\"") {
		t.Error("Expected <a> tag for links")
	}

	// Check content type was changed
	if resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("Expected Content-Type to be text/html; charset=utf-8, got %s", resp.Header.Get("Content-Type"))
	}
}

func TestMarkdownTransform_Tables(t *testing.T) {
	markdown := `| Header 1 | Header 2 |
|----------|----------|
| Cell 1   | Cell 2   |
| Cell 3   | Cell 4   |
`

	config := &MarkdownTransform{
		DisableTables: false,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(markdown)),
	}
	resp.Header.Set("Content-Type", "text/markdown")

	err := config.tr.Modify(resp)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	html := string(body)

	if !strings.Contains(html, "<table>") {
		t.Error("Expected <table> tag")
	}
	if !strings.Contains(html, "<thead>") {
		t.Error("Expected <thead> tag")
	}
	if !strings.Contains(html, "<tbody>") {
		t.Error("Expected <tbody> tag")
	}
	if !strings.Contains(html, "<th>") {
		t.Error("Expected <th> tag for headers")
	}
	if !strings.Contains(html, "<td>") {
		t.Error("Expected <td> tag for cells")
	}
}

func TestMarkdownTransform_CodeBlocks(t *testing.T) {
	markdown := "```go\nfunc main() {\n    fmt.Println(\"Hello\")\n}\n```"

	config := &MarkdownTransform{
		DisableFencedCode: false,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(markdown)),
	}
	resp.Header.Set("Content-Type", "text/markdown")

	err := config.tr.Modify(resp)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	html := string(body)

	if !strings.Contains(html, "<pre>") {
		t.Error("Expected <pre> tag for code block")
	}
	if !strings.Contains(html, "<code") {
		t.Error("Expected <code> tag for code block")
	}
}

func TestMarkdownTransform_Strikethrough(t *testing.T) {
	markdown := "This is ~~strikethrough~~ text."

	config := &MarkdownTransform{
		DisableStrikethrough: false,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(markdown)),
	}
	resp.Header.Set("Content-Type", "text/markdown")

	err := config.tr.Modify(resp)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	html := string(body)

	if !strings.Contains(html, "<del>") {
		t.Error("Expected <del> tag for strikethrough")
	}
}

func TestMarkdownTransform_Autolink(t *testing.T) {
	markdown := "Check out https://example.com for more info."

	config := &MarkdownTransform{
		DisableAutolink: false,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(markdown)),
	}
	resp.Header.Set("Content-Type", "text/markdown")

	err := config.tr.Modify(resp)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	html := string(body)

	if !strings.Contains(html, "<a href=\"https://example.com\"") {
		t.Error("Expected auto-linked URL")
	}
}

func TestMarkdownTransform_SanitizeHTML(t *testing.T) {
	markdown := "# Title\n\n<script>alert('xss')</script>\n\nNormal text."

	config := &MarkdownTransform{
		SkipHTML: true,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(markdown)),
	}
	resp.Header.Set("Content-Type", "text/markdown")

	err := config.tr.Modify(resp)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	html := string(body)

	// With SkipHTML, the script tag should not be in the output
	if strings.Contains(html, "<script>") {
		t.Error("Expected script tag to be stripped with SkipHTML enabled")
	}
}

func TestMarkdownTransform_TargetBlank(t *testing.T) {
	markdown := "[Link](https://example.com)"

	config := &MarkdownTransform{
		HrefTargetBlank: true,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(markdown)),
	}
	resp.Header.Set("Content-Type", "text/markdown")

	err := config.tr.Modify(resp)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	html := string(body)

	if !strings.Contains(html, "target=\"_blank\"") {
		t.Error("Expected target=\"_blank\" in link")
	}
}

func TestMarkdownTransform_ContentTypeFilter(t *testing.T) {
	markdown := "# Hello"

	config := &MarkdownTransform{}
	config.ContentTypes = []string{"text/markdown"}
	config.tr = createMarkdownTransform(config)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(markdown)),
	}
	resp.Header.Set("Content-Type", "text/plain")

	err := config.tr.Modify(resp)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	// Body should be unchanged since content type doesn't match
	if !bytes.Equal(body, []byte(markdown)) {
		t.Error("Expected body to be unchanged for non-matching content type")
	}
}

func BenchmarkMarkdownTransform_Small(b *testing.B) {
	b.ReportAllocs()
	markdown := `# Hello World

This is a simple **markdown** document.
`

	config := &MarkdownTransform{
		DisableTables:     false,
		DisableFencedCode: false,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(markdown)),
		}
		resp.Header.Set("Content-Type", "text/markdown")

		_ = config.tr.Modify(resp)
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkMarkdownTransform_Large(b *testing.B) {
	b.ReportAllocs()
	// Create a large markdown document
	var buf bytes.Buffer
	buf.WriteString("# Large Document\n\n")
	for i := 0; i < 100; i++ {
		buf.WriteString("## Section ")
		buf.WriteString(string(rune(i)))
		buf.WriteString("\n\nThis is paragraph with **bold** and *italic* text.\n\n")
		buf.WriteString("- List item 1\n- List item 2\n- List item 3\n\n")
		buf.WriteString("[Link](https://example.com)\n\n")
	}
	markdown := buf.String()

	config := &MarkdownTransform{
		DisableTables:     false,
		DisableFencedCode: false,
	}
	config.ContentTypes = MarkdownContentTypes
	config.tr = createMarkdownTransform(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(markdown)),
		}
		resp.Header.Set("Content-Type", "text/markdown")

		_ = config.tr.Modify(resp)
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
}

