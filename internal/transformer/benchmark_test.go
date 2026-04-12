package transformer

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// BenchmarkHTMLTransformer benchmarks HTML transformation
func BenchmarkHTMLTransformer(b *testing.B) {
	b.ReportAllocs()
	htmlContent := `<html><head><title>Test</title></head><body><h1>Hello World</h1><p>This is a test paragraph.</p></body></html>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(htmlContent)
		transformer := &HTMLTransformer{
			tokenizer: html.NewTokenizer(io.NopCloser(reader)),
			buffer:    &bytes.Buffer{},
			closer:    io.NopCloser(reader),
		}

		// Read the transformed content
		buffer := make([]byte, 1024)
		for {
			n, err := transformer.Read(buffer)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			_ = n
		}

		transformer.Close()
	}
}

// BenchmarkHTMLTransformerWithModifications benchmarks HTML transformation with modifications
func BenchmarkHTMLTransformerWithModifications(b *testing.B) {
	b.ReportAllocs()
	htmlContent := `<html><head><title>Test</title></head><body><h1>Hello World</h1><p>This is a test paragraph.</p><img src="test.jpg" alt="Test Image"></body></html>`

	// Create modification function
	modifyFn := func(token html.Token, w io.Writer) error {
		if token.Type == html.StartTagToken && token.Data == "img" {
			// Add loading="lazy" to img tags
			for i, attr := range token.Attr {
				if attr.Key == "loading" {
					token.Attr[i].Val = "lazy"
					break
				}
			}
			// If loading attribute doesn't exist, add it
			if !hasAttr(token, "loading") {
				token.Attr = append(token.Attr, html.Attribute{Key: "loading", Val: "lazy"})
			}
		}
		return nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(htmlContent)
		transformer := &HTMLTransformer{
			tokenizer: html.NewTokenizer(io.NopCloser(reader)),
			buffer:    &bytes.Buffer{},
			closer:    io.NopCloser(reader),
			fns:       []ModifyFn{modifyFn},
		}

		// Read the transformed content
		buffer := make([]byte, 1024)
		for {
			n, err := transformer.Read(buffer)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			_ = n
		}

		transformer.Close()
	}
}

// BenchmarkHTMLTokenizer benchmarks HTML tokenization
func BenchmarkHTMLTokenizer(b *testing.B) {
	b.ReportAllocs()
	htmlContent := `<html><head><title>Test</title></head><body><h1>Hello World</h1><p>This is a test paragraph with <strong>bold</strong> and <em>italic</em> text.</p><img src="test.jpg" alt="Test Image"><a href="http://example.com">Link</a></body></html>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(htmlContent)
		tokenizer := html.NewTokenizer(reader)

		for {
			tokenType := tokenizer.Next()
			if tokenType == html.ErrorToken {
				break
			}

			token := tokenizer.Token()
			_ = token
		}
	}
}

// BenchmarkContentTypeDetection benchmarks content type detection
func BenchmarkContentTypeDetection(b *testing.B) {
	b.ReportAllocs()
	contentTypes := []string{
		"text/html",
		"application/json",
		"text/plain",
		"application/xml",
		"image/jpeg",
		"image/png",
		"application/pdf",
		"text/css",
		"application/javascript",
		"text/csv",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ct := range contentTypes {
			// Simulate content type detection
			_ = strings.Contains(ct, "html")
			_ = strings.Contains(ct, "json")
			_ = strings.Contains(ct, "xml")
			_ = strings.Contains(ct, "image")
		}
	}
}

// BenchmarkURLTransformation benchmarks URL transformation
func BenchmarkURLTransformation(b *testing.B) {
	b.ReportAllocs()
	urls := []string{
		"http://example.com/path",
		"https://example.com/path?param=value",
		"http://example.com/path#fragment",
		"https://example.com/path?param1=value1&param2=value2#fragment",
		"http://subdomain.example.com/path",
		"https://example.com:8080/path",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, urlStr := range urls {
			// Simulate URL transformation
			_ = strings.Replace(urlStr, "http://", "https://", 1)
			_ = strings.Replace(urlStr, "example.com", "transformed.example.com", 1)
		}
	}
}

// BenchmarkTagReplacement benchmarks tag replacement operations
func BenchmarkTagReplacement(b *testing.B) {
	b.ReportAllocs()
	htmlContent := `<html><head><title>Test</title></head><body><h1>Hello World</h1><p>This is a test paragraph.</p><img src="test.jpg" alt="Test Image"></body></html>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate tag replacement
		content := htmlContent
		content = strings.Replace(content, "<img", "<img loading=\"lazy\"", -1)
		content = strings.Replace(content, "<script", "<script async", -1)
		content = strings.Replace(content, "<link", "<link crossorigin", -1)
		_ = content
	}
}

// BenchmarkBufferOperations benchmarks buffer operations
func BenchmarkBufferOperations(b *testing.B) {
	b.ReportAllocs()
	data := []byte("test data for buffer operations benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buffer := bytes.NewBuffer(make([]byte, 0, 1024))

		// Write data to buffer
		buffer.Write(data)
		buffer.WriteString(" additional data")
		buffer.WriteByte('!')

		// Read from buffer
		_ = buffer.Bytes()
		_ = buffer.String()
		_ = buffer.Len()
	}
}

// BenchmarkHTMLParsing benchmarks HTML parsing operations
func BenchmarkHTMLParsing(b *testing.B) {
	b.ReportAllocs()
	htmlContent := `<html><head><title>Test</title></head><body><h1>Hello World</h1><p>This is a test paragraph with <strong>bold</strong> and <em>italic</em> text.</p><img src="test.jpg" alt="Test Image"><a href="http://example.com">Link</a></body></html>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(htmlContent)
		doc, err := html.Parse(reader)
		if err != nil {
			b.Fatal(err)
		}
		_ = doc
	}
}

// BenchmarkEncodingDetection benchmarks encoding detection
func BenchmarkEncodingDetection(b *testing.B) {
	b.ReportAllocs()
	contentTypes := []string{
		"text/html; charset=utf-8",
		"text/html; charset=iso-8859-1",
		"application/json; charset=utf-8",
		"text/plain; charset=ascii",
		"application/xml; charset=utf-8",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ct := range contentTypes {
			// Extract charset
			parts := strings.Split(ct, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "charset=") {
					charset := strings.TrimPrefix(part, "charset=")
					_ = charset
				}
			}
		}
	}
}

// BenchmarkHTTPResponseProcessing benchmarks HTTP response processing
func BenchmarkHTTPResponseProcessing(b *testing.B) {
	b.ReportAllocs()
	headers := http.Header{
		"Content-Type":   []string{"text/html; charset=utf-8"},
		"Content-Length": []string{"1024"},
		"Cache-Control":  []string{"max-age=3600"},
		"ETag":           []string{"\"abc123\""},
		"Last-Modified":  []string{"Wed, 21 Oct 2015 07:28:00 GMT"},
	}

	body := []byte("<html><head><title>Test</title></head><body><h1>Hello World</h1></body></html>")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Process headers
		contentType := headers.Get("Content-Type")
		contentLength := headers.Get("Content-Length")
		cacheControl := headers.Get("Cache-Control")

		// Process body
		_ = len(body)
		_ = strings.Contains(string(body), "html")
		_ = strings.Contains(string(body), "title")

		// Simulate content type checking
		_ = strings.Contains(contentType, "html")
		_ = strings.Contains(contentType, "utf-8")
		_ = contentLength
		_ = cacheControl
	}
}

// BenchmarkStringOperations benchmarks string operations
func BenchmarkStringOperations(b *testing.B) {
	b.ReportAllocs()
	htmlContent := `<html><head><title>Test</title></head><body><h1>Hello World</h1><p>This is a test paragraph.</p></body></html>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// String operations
		_ = strings.ToLower(htmlContent)
		_ = strings.ToUpper(htmlContent)
		_ = strings.Contains(htmlContent, "html")
		_ = strings.Contains(htmlContent, "title")
		_ = strings.Contains(htmlContent, "body")
		_ = strings.Index(htmlContent, "<h1>")
		_ = strings.Index(htmlContent, "</h1>")
	}
}

// BenchmarkMemoryAllocations benchmarks memory allocations in transform operations
func BenchmarkMemoryAllocations(b *testing.B) {
	b.ReportAllocs()

	htmlContent := `<html><head><title>Test</title></head><body><h1>Hello World</h1><p>This is a test paragraph.</p></body></html>`

	for i := 0; i < b.N; i++ {
		// Allocate buffers and strings
		buffer := bytes.NewBuffer(make([]byte, 0, 1024))
		buffer.WriteString(htmlContent)

		// String operations that may allocate
		lower := strings.ToLower(htmlContent)
		upper := strings.ToUpper(htmlContent)
		replaced := strings.Replace(htmlContent, "html", "HTML", -1)

		_ = buffer
		_ = lower
		_ = upper
		_ = replaced
	}
}

// Helper function to check if an attribute exists
func hasAttr(token html.Token, key string) bool {
	for _, attr := range token.Attr {
		if attr.Key == key {
			return true
		}
	}
	return false
}
