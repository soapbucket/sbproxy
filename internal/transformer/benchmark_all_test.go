package transformer

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

var (
	benchmarkHTML = `<html><head><title>Test</title></head><body><h1>Hello World</h1><p>This is a test paragraph with <strong>bold</strong> and <em>italic</em> text.</p><img src="test.jpg" alt="Test Image"><a href="http://example.com">Link</a></body></html>`
	benchmarkJS   string
	benchmarkCSS  string
	benchmarkJSON string
)

func init() {
	// Load fixtures for benchmarks
	if jsData, err := os.ReadFile("fixtures/test.js"); err == nil {
		benchmarkJS = string(jsData)
	} else {
		benchmarkJS = `function add(a, b) { return a + b; } const multiply = function(x, y) { return x * y; }; let result = add(5, 10); console.log('Result:', result);`
	}
	
	if cssData, err := os.ReadFile("fixtures/test.css"); err == nil {
		benchmarkCSS = string(cssData)
	} else {
		benchmarkCSS = `body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #ffffff; } .container { width: 100%; max-width: 1200px; margin: 0 auto; }`
	}
	
	if jsonData, err := os.ReadFile("fixtures/test.json"); err == nil {
		benchmarkJSON = string(jsonData)
	} else {
		benchmarkJSON = `{"name":"test","value":123,"nested":{"prop":"value"}}`
	}
}

// BenchmarkMinifyJavascript benchmarks JavaScript minification
func BenchmarkMinifyJavascript(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkJS)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.js", nil),
	}
	resp.Header.Set("Content-Type", "application/javascript")
	
	transform := MinifyJavascript(MinifyJavascriptOptions{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkJS))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkMinifyJavascript_WithOptions benchmarks JavaScript minification with options
func BenchmarkMinifyJavascript_WithOptions(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkJS)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.js", nil),
	}
	resp.Header.Set("Content-Type", "application/javascript")
	
	transform := MinifyJavascript(MinifyJavascriptOptions{
		Precision:    2,
		KeepVarNames: true,
		Version:      5,
	})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkJS))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkMinifyCSS benchmarks CSS minification
func BenchmarkMinifyCSS(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkCSS)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.css", nil),
	}
	resp.Header.Set("Content-Type", "text/css")
	
	transform := MinifyCSS(MinifyCSSOptions{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkCSS))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkMinifyCSS_WithOptions benchmarks CSS minification with options
func BenchmarkMinifyCSS_WithOptions(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkCSS)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.css", nil),
	}
	resp.Header.Set("Content-Type", "text/css")
	
	transform := MinifyCSS(MinifyCSSOptions{
		Precision: 2,
		Inline:    true,
		Version:   3,
	})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkCSS))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkOptimizeHTML benchmarks HTML optimization
func BenchmarkOptimizeHTML(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkHTML)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.html", nil),
	}
	resp.Header.Set("Content-Type", "text/html")
	
	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
		RemoveBooleanAttributes: true,
		StripComments:           true,
		OptimizeAttributes:      true,
	}))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkHTML))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkOptimizeHTML_Lowercase benchmarks HTML optimization with lowercasing
func BenchmarkOptimizeHTML_Lowercase(b *testing.B) {
	b.ReportAllocs()
	
	htmlInput := `<DIV CLASS="test" ID="main">Content</DIV>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(htmlInput)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.html", nil),
	}
	resp.Header.Set("Content-Type", "text/html")
	
	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
		LowercaseTags:       true,
		LowercaseAttributes: true,
	}))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(htmlInput))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkStripSpace benchmarks whitespace stripping
func BenchmarkStripSpace(b *testing.B) {
	b.ReportAllocs()
	
	htmlInput := `<div>   Content   with   spaces   </div>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(htmlInput)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.html", nil),
	}
	resp.Header.Set("Content-Type", "text/html")
	
	transform := ModifyHTML(StripSpace(StripSpaceOptions{
		StripNewlines:    true,
		StripExtraSpaces: true,
	}))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(htmlInput))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkAddUniqueID benchmarks unique ID addition
func BenchmarkAddUniqueID(b *testing.B) {
	b.ReportAllocs()
	
	htmlInput := `<div>Content</div><p>Text</p><span>More</span>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(htmlInput)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.html", nil),
	}
	resp.Header.Set("Content-Type", "text/html")
	
	transform := ModifyHTML(AddUniqueID(AddUniqueIDOptions{
		Prefix: "test",
	}))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(htmlInput))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkOptimizeJSON benchmarks JSON optimization
func BenchmarkOptimizeJSON(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkJSON)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.json", nil),
	}
	resp.Header.Set("Content-Type", "application/json")
	
	transform := OptimizeJSON(JSONOptions{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkJSON))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkOptimizeJSON_WithPruning benchmarks JSON optimization with pruning
func BenchmarkOptimizeJSON_WithPruning(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkJSON)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.json", nil),
	}
	resp.Header.Set("Content-Type", "application/json")
	
	transform := OptimizeJSON(JSONOptions{
		RemoveEmptyStrings:  true,
		RemoveFalseBooleans: true,
		RemoveZeroNumbers:   true,
		RemoveEmptyObjects:  true,
		RemoveEmptyArrays:   true,
	})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkJSON))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkDiscard benchmarks discarding bytes
func BenchmarkDiscard(b *testing.B) {
	b.ReportAllocs()
	
	input := strings.Repeat("Hello World ", 100)
	resp := &http.Response{
		Body: io.NopCloser(strings.NewReader(input)),
	}
	
	transform := Discard(50)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(input))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkNoop benchmarks no-op transform
func BenchmarkNoop(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkHTML)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.html", nil),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkHTML))
		if err := Noop.Modify(resp); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFixEncoding benchmarks encoding fix
func BenchmarkFixEncoding(b *testing.B) {
	b.ReportAllocs()
	
	// Create gzipped content
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(benchmarkHTML))
	gz.Close()
	gzipped := buf.Bytes()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Body:    io.NopCloser(bytes.NewReader(gzipped)),
			Header:  make(http.Header),
			Request: httptest.NewRequest("GET", "http://example.com/test.html", nil),
		}
		resp.Header.Set("Content-Encoding", "gzip")
		
		transform := FixEncoding()
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkHTMLTokenizer_All benchmarks HTML tokenization
func BenchmarkHTMLTokenizer_All(b *testing.B) {
	b.ReportAllocs()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(benchmarkHTML)
		tokenizer := html.NewTokenizer(reader)
		
		for {
			tokenType := tokenizer.Next()
			if tokenType == html.ErrorToken {
				break
			}
			_ = tokenizer.Token()
		}
	}
}

// BenchmarkHTMLTransformer_WithMultipleModifiers benchmarks HTML transformer with multiple modifiers
func BenchmarkHTMLTransformer_WithMultipleModifiers(b *testing.B) {
	b.ReportAllocs()
	
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(benchmarkHTML)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/test.html", nil),
	}
	resp.Header.Set("Content-Type", "text/html")
	
	transform := ModifyHTML(
		OptimizeHTML(OptimizeHTMLOptions{
			LowercaseTags:       true,
			LowercaseAttributes: true,
			StripComments:       true,
		}),
		StripSpace(StripSpaceOptions{
			StripNewlines: true,
		}),
		AddUniqueID(AddUniqueIDOptions{
			Prefix: "test",
		}),
	)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(benchmarkHTML))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkLargeFile_JavaScript benchmarks minification of large JavaScript file
func BenchmarkLargeFile_JavaScript(b *testing.B) {
	b.ReportAllocs()
	
	// Wrap in block scopes {} so const/let declarations don't conflict when repeated
	largeJS := strings.Repeat("{\n"+benchmarkJS+"\n}\n", 100)
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(largeJS)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/large.js", nil),
	}
	resp.Header.Set("Content-Type", "application/javascript")
	
	transform := MinifyJavascript(MinifyJavascriptOptions{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(largeJS))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkLargeFile_CSS benchmarks minification of large CSS file
func BenchmarkLargeFile_CSS(b *testing.B) {
	b.ReportAllocs()
	
	largeCSS := strings.Repeat(benchmarkCSS+"\n", 100)
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(largeCSS)),
		Header:  make(http.Header),
		Request: httptest.NewRequest("GET", "http://example.com/large.css", nil),
	}
	resp.Header.Set("Content-Type", "text/css")
	
	transform := MinifyCSS(MinifyCSSOptions{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(strings.NewReader(largeCSS))
		if err := transform.Modify(resp); err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

