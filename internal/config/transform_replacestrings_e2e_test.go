package config

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// TestReplaceStringsTransformE2E tests the string replace transform end-to-end
// This test simulates the actual e2e test scenario
func TestReplaceStringsTransformE2E(t *testing.T) {
	// Simulate the actual configuration from 09-string-replace.json
	configJSON := `{
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
	}`

	transform, err := NewReplaceStringsTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	// Simulate HTML content from example.com
	// Include "example.com" in the content to test regex replacement
	inputHTML := `<!doctype html>
<html>
<head>
    <title>Example Domain</title>
    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p>Visit example.com for more information.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>`

	expectedReplacements := []string{
		"Proxied Example Domain", // Should replace "Example Domain"
		"proxy.example.com",      // Should replace "example.com" (regex)
	}

	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader([]byte(inputHTML))),
		Request: &http.Request{
			URL: &url.URL{Path: "/test"},
		},
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	err = transform.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error applying transform: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	result := string(body)

	// Check that replacements were made
	for _, expected := range expectedReplacements {
		if !bytes.Contains(body, []byte(expected)) {
			t.Errorf("expected replacement %q not found in result", expected)
		}
	}

	// Check that original strings are not present
	if bytes.Contains(body, []byte("Example Domain")) && !bytes.Contains(body, []byte("Proxied Example Domain")) {
		t.Error("original 'Example Domain' still present without replacement")
	}

	// Check that regex replacement worked (example.com should be replaced)
	// Note: This will fail if regex is not implemented
	if bytes.Contains(body, []byte("example.com")) && !bytes.Contains(body, []byte("proxy.example.com")) {
		t.Error("regex replacement for 'example.com' did not work")
	}

	t.Logf("Result length: %d bytes", len(result))
	t.Logf("First 500 chars of result:\n%s", result[:min(500, len(result))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

