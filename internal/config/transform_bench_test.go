package config

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// Benchmark for encoding transform
func BenchmarkEncodingTransform(b *testing.B) {
	b.ReportAllocs()
	input := []byte("Hello, World! This is a test of the encoding transform.")
	transform, _ := NewDefaultEncodingTransform(false, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/plain")

		_ = transform.Apply(resp)
	}
}

// Benchmark for JSON transform with remove empty objects
func BenchmarkJSONTransform_RemoveEmptyObjects(b *testing.B) {
	b.ReportAllocs()
	input := []byte(`{"data": {"name": "test", "empty": {}, "nested": {"value": 1, "empty": {}}}, "another": {}}`)
	transform, _ := NewJSONTransform([]byte(`{"type":"json","remove_empty_objects":true}`))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "application/json")

		_ = transform.Apply(resp)
	}
}

// Benchmark for JSON transform with pretty print
func BenchmarkJSONTransform_PrettyPrint(b *testing.B) {
	b.ReportAllocs()
	input := []byte(`{"data":{"name":"test","value":123},"array":[1,2,3,4,5]}`)
	transform, _ := NewJSONTransform([]byte(`{"type":"json","pretty_print":true}`))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "application/json")

		_ = transform.Apply(resp)
	}
}

// Benchmark for replace strings with single replacement
func BenchmarkReplaceStrings_Single(b *testing.B) {
	b.ReportAllocs()
	input := []byte("Hello, old world! This is the old way of doing things.")
	transform, _ := NewReplaceStringsTransform([]byte(`{
		"type": "replace_strings",
		"replace_strings": {
			"replacements": [{"find": "old", "replace": "new"}]
		}
	}`))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/html")

		_ = transform.Apply(resp)
	}
}

// Benchmark for replace strings with multiple replacements
func BenchmarkReplaceStrings_Multiple(b *testing.B) {
	b.ReportAllocs()
	input := []byte("Hello foo, how are you bar? The foo is great and bar is awesome!")
	transform, _ := NewReplaceStringsTransform([]byte(`{
		"type": "replace_strings",
		"replace_strings": {
			"replacements": [
				{"find": "foo", "replace": "baz"},
				{"find": "bar", "replace": "qux"},
				{"find": "great", "replace": "excellent"},
				{"find": "awesome", "replace": "fantastic"}
			]
		}
	}`))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/html")

		_ = transform.Apply(resp)
	}
}

// Benchmark for discard transform
func BenchmarkDiscardTransform(b *testing.B) {
	b.ReportAllocs()
	input := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	transform, _ := NewDiscardTransform([]byte(`{"type":"discard","bytes":10}`))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/plain")

		_ = transform.Apply(resp)
	}
}

// Benchmark for HTML transform with format options
func BenchmarkHTMLTransform(b *testing.B) {
	b.ReportAllocs()
	input := []byte(`<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <div class="container">
        <h1>Hello World</h1>
        <p>This is a test paragraph.</p>
    </div>
</body>
</html>`)
	transform, _ := NewHTMLTransform([]byte(`{
		"type": "html",
		"format_options": {
			"strip_newlines": true,
			"strip_space": true
		}
	}`))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/html")

		_ = transform.Apply(resp)
	}
}

// Benchmark for optimized HTML transform
func BenchmarkOptimizedHTMLTransform(b *testing.B) {
	b.ReportAllocs()
	input := []byte(`<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <div class="container">
        <h1>Hello World</h1>
        <p>This is a test paragraph.</p>
    </div>
</body>
</html>`)
	transform, _ := NewOptimizedHTMLTransform([]byte(`{
		"type": "optimized_html",
		"format_options": {
			"strip_newlines": true,
			"strip_space": true,
			"strip_comments": true
		}
	}`))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/html")

		_ = transform.Apply(resp)
	}
}

// Benchmark comparison: HTML vs Optimized HTML
func BenchmarkHTMLTransform_Comparison(b *testing.B) {
	b.ReportAllocs()
	input := []byte(`<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <div class="container">
        <h1>Hello World</h1>
        <p>This is a test paragraph with some content.</p>
        <ul>
            <li>Item 1</li>
            <li>Item 2</li>
            <li>Item 3</li>
        </ul>
    </div>
</body>
</html>`)

	b.Run("Standard HTML Transform", func(b *testing.B) {
		transform, _ := NewHTMLTransform([]byte(`{"type":"html","format_options":{"strip_newlines":true}}`))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp := &http.Response{
				Header:  make(http.Header),
				Body:    io.NopCloser(bytes.NewReader(input)),
				Request: &http.Request{URL: &url.URL{Path: "/test"}},
			}
			resp.Header.Set("Content-Type", "text/html")
			_ = transform.Apply(resp)
		}
	})

	b.Run("Optimized HTML Transform", func(b *testing.B) {
		transform, _ := NewOptimizedHTMLTransform([]byte(`{"type":"optimized_html","format_options":{"strip_newlines":true}}`))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp := &http.Response{
				Header:  make(http.Header),
				Body:    io.NopCloser(bytes.NewReader(input)),
				Request: &http.Request{URL: &url.URL{Path: "/test"}},
			}
			resp.Header.Set("Content-Type", "text/html")
			_ = transform.Apply(resp)
		}
	})
}

// Benchmark for transform chain (multiple transforms)
func BenchmarkTransformChain(b *testing.B) {
	b.ReportAllocs()
	input := []byte("Hello, old world!")

	encoding, _ := NewDefaultEncodingTransform(false, false)
	replace, _ := NewReplaceStringsTransform([]byte(`{
		"type": "replace_strings",
		"replace_strings": {
			"replacements": [{"find": "old", "replace": "new"}]
		}
	}`))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/html")

		// Apply transforms in chain
		_ = encoding.Apply(resp)
		
		// Need to reset body for next transform
		body, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		
		_ = replace.Apply(resp)
	}
}

