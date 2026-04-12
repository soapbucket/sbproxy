package transformer

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTMLAddToTagPrepend tests that add_to_tags works correctly with regular HTML transform
func TestHTMLAddToTagPrepend(t *testing.T) {
	htmlContent := `<html>
<head>
<style></style>
</head>
<body>
asdf
</body>
</html>`

	expectedOutput := `<html>
<head><meta name="proxy" content="enabled">
<style></style>
</head>
<body>
asdf
<!-- Proxy injected content --></body>
</html>`

	// Create a mock HTTP request
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Create a mock HTTP response
	resp := &http.Response{
		Request: req,
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader(htmlContent)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// Create the HTML transform with add_to_tags
	transform := ModifyHTML(
		AddToTagPrepend("head", "<meta name=\"proxy\" content=\"enabled\">", false),
		AddToTagPrepend("body", "<!-- Proxy injected content -->", true),
	)

	// Apply the transform
	err := transform.Modify(resp)
	require.NoError(t, err)

	// Read the transformed content
	var result bytes.Buffer
	buffer := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buffer)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		result.Write(buffer[:n])
	}

	output := result.String()
	assert.Equal(t, expectedOutput, output, "Regular HTML transform should add content correctly")
}

// TestHTMLAddToTagEnd tests that prepend: true works for body tag in regular HTML
func TestHTMLAddToTagEnd(t *testing.T) {
	htmlContent := `<html>
<head>
</head>
<body>
content
</body>
</html>`

	expectedOutput := `<html>
<head>
</head>
<body>
content
<!-- Proxy injected content --></body>
</html>`

	// Create a mock HTTP request
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Create a mock HTTP response
	resp := &http.Response{
		Request: req,
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader(htmlContent)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// Create the HTML transform with add_to_tags
	transform := ModifyHTML(
		AddToTagPrepend("body", "<!-- Proxy injected content -->", true),
	)

	// Apply the transform
	err := transform.Modify(resp)
	require.NoError(t, err)

	// Read the transformed content
	var result bytes.Buffer
	buffer := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buffer)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		result.Write(buffer[:n])
	}

	output := result.String()
	assert.Equal(t, expectedOutput, output, "Regular HTML transform should add content before closing body tag")
}
