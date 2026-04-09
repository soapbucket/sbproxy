package config

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// TestConfigTransformOrderE2E tests that FixEncoding is applied before StringReplacement
// when transforms are explicitly specified in the config. This is critical for handling
// gzipped responses from upstream servers.
func TestConfigTransformOrderE2E(t *testing.T) {
	t.Run("FixEncoding applied before StringReplacement with gzipped content", func(t *testing.T) {
		// Simulate the actual configuration from 09-string-replace.json
		// This config explicitly specifies replace_strings transform
		configJSON := `{
			"id": "string-replace",
			"hostname": "string-replace.test",
			"action": {
				"type": "proxy",
				"url": "https://example.com"
			},
			"transforms": [
				{
					"type": "replace_strings",
					"content_types": ["text/html", "text/plain"],
					"replace_strings": {
						"replacements": [
							{
								"find": "Example Domain",
								"replace": "Proxied Example Domain",
								"regex": false
							},
							{
								"find": "example\\.com",
								"replace": "proxy.example.com",
								"regex": true
							}
						]
					}
				}
			]
		}`

		// Load the config - this should automatically prepend FixEncoding transform
		cfg := &Config{}
		err := cfg.UnmarshalJSON([]byte(configJSON))
		if err != nil {
			t.Fatalf("failed to unmarshal config: %v", err)
		}

		// Verify that transforms are loaded
		if len(cfg.transforms) == 0 {
			t.Fatal("expected transforms to be loaded, got 0")
		}

		// Verify that FixEncoding is first (prepended)
		firstTransform := cfg.transforms[0]
		if firstTransform.GetType() != TransformEncoding {
			t.Errorf("expected first transform to be Encoding (FixEncoding), got %s", firstTransform.GetType())
		}

		// Verify that StringReplacement is second
		if len(cfg.transforms) < 2 {
			t.Fatal("expected at least 2 transforms (Encoding + StringReplacement)")
		}
		secondTransform := cfg.transforms[1]
		if secondTransform.GetType() != TransformReplaceStrings {
			t.Errorf("expected second transform to be ReplaceStrings, got %s", secondTransform.GetType())
		}

		// Create gzipped HTML content (simulating response from example.com)
		originalHTML := `<!doctype html>
<html>
<head>
    <title>Example Domain</title>
</head>
<body>
    <h1>Example Domain</h1>
    <p>Visit example.com for more information.</p>
</body>
</html>`

		// Compress the HTML content
		var gzipBuf bytes.Buffer
		gzipWriter := gzip.NewWriter(&gzipBuf)
		_, err = gzipWriter.Write([]byte(originalHTML))
		if err != nil {
			t.Fatalf("failed to write gzip: %v", err)
		}
		if err = gzipWriter.Close(); err != nil {
			t.Fatalf("failed to close gzip writer: %v", err)
		}

		// Create HTTP response with gzipped content
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(gzipBuf.Bytes())),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		resp.Header.Set("Content-Encoding", "gzip")
		resp.ContentLength = int64(gzipBuf.Len())

		// Apply transforms using ModifyResponse (simulating actual proxy behavior)
		modifyFn := cfg.ModifyResponse()
		err = modifyFn(resp)
		if err != nil {
			t.Fatalf("unexpected error applying transforms: %v", err)
		}

		// Verify Content-Encoding header was removed (FixEncoding should have done this)
		if resp.Header.Get("Content-Encoding") != "" {
			t.Errorf("expected Content-Encoding header to be removed, got %q", resp.Header.Get("Content-Encoding"))
		}

		// Read the transformed body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		result := string(body)

		// Verify the content is decompressed (not gzipped binary data)
		if bytes.HasPrefix(body, []byte{0x1f, 0x8b}) {
			t.Error("body still appears to be gzipped (starts with gzip magic bytes)")
		}

		// Verify string replacements were applied to the decompressed content
		if !bytes.Contains(body, []byte("Proxied Example Domain")) {
			t.Error("expected 'Proxied Example Domain' in result (string replacement not applied)")
		}

		if !bytes.Contains(body, []byte("proxy.example.com")) {
			t.Error("expected 'proxy.example.com' in result (regex replacement not applied)")
		}

		// Verify original strings are replaced
		if bytes.Contains(body, []byte("Example Domain")) && !bytes.Contains(body, []byte("Proxied Example Domain")) {
			t.Error("original 'Example Domain' still present without replacement")
		}

		// Verify HTML structure is intact (decompression worked)
		if !bytes.Contains(body, []byte("<html>")) {
			t.Error("HTML structure appears corrupted (decompression may have failed)")
		}

		t.Logf("Transform order verified:")
		for i, tr := range cfg.transforms {
			t.Logf("  [%d] %s", i, tr.GetType())
		}
		t.Logf("Result length: %d bytes", len(result))
		firstChars := 200
		if len(result) < firstChars {
			firstChars = len(result)
		}
		t.Logf("First %d chars of result:\n%s", firstChars, result[:firstChars])
	})

	t.Run("Encoding transform always prepended when transforms specified", func(t *testing.T) {
		configJSON := `{
			"id": "string-replace",
			"hostname": "string-replace.test",
			"action": {
				"type": "proxy",
				"url": "https://example.com"
			},
			"transforms": [
				{
					"type": "replace_strings",
					"replace_strings": {
						"replacements": [
							{
								"find": "test",
								"replace": "replaced"
							}
						]
					}
				}
			]
		}`

		cfg := &Config{}
		err := cfg.UnmarshalJSON([]byte(configJSON))
		if err != nil {
			t.Fatalf("failed to unmarshal config: %v", err)
		}

		// Encoding transform is always prepended when transforms are specified
		if len(cfg.transforms) < 2 {
			t.Errorf("expected at least 2 transforms (Encoding + ReplaceStrings), got %d", len(cfg.transforms))
		}

		// First transform should be Encoding (both FixEncoding and FixContentType always enabled)
		if cfg.transforms[0].GetType() != TransformEncoding {
			t.Errorf("expected first transform to be Encoding, got %s", cfg.transforms[0].GetType())
		}

		// Second transform should be ReplaceStrings
		if cfg.transforms[1].GetType() != TransformReplaceStrings {
			t.Errorf("expected second transform to be ReplaceStrings, got %s", cfg.transforms[1].GetType())
		}
	})

	t.Run("FixEncoding applied when no transforms specified", func(t *testing.T) {
		configJSON := `{
			"id": "basic-proxy",
			"hostname": "basic-proxy.test",
			"action": {
				"type": "proxy",
				"url": "https://example.com"
			}
		}`

		cfg := &Config{}
		err := cfg.UnmarshalJSON([]byte(configJSON))
		if err != nil {
			t.Fatalf("failed to unmarshal config: %v", err)
		}

		// When no transforms are specified, FixEncoding should be added by default
		if len(cfg.transforms) == 0 {
			t.Fatal("expected default Encoding transform to be added")
		}

		if cfg.transforms[0].GetType() != TransformEncoding {
			t.Errorf("expected default transform to be Encoding, got %s", cfg.transforms[0].GetType())
		}
	})
}

