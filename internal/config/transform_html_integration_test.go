package config

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTMLTransformAddBeforeEndTagIntegration(t *testing.T) {
	htmlContent := `<html>
<head>
<style></style>
</head>
<body>
content
</body>
</html>`

	expectedOutput := `<html>
<head>
<style></style>
</head>
<body>
content
<!-- Test --></body>
</html>`

	// Test with add_before_end_tag: true
	configJSON := `{
		"type": "html",
		"add_to_tags": [{
			"tag": "body",
			"add_before_end_tag": true,
			"content": "<!-- Test -->"
		}]
	}`

	cfg, err := NewHTMLTransform([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	htmlCfg := cfg.(*HTMLTransformConfig)
	require.NotNil(t, htmlCfg.tr)

	// Create a mock HTTP response
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp := &http.Response{
		Request: req,
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader(htmlContent)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// Apply the transform
	err = htmlCfg.tr.Modify(resp)
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
	assert.Equal(t, expectedOutput, output, "HTML transform should add content before closing body tag when add_before_end_tag: true")
}

func TestOptimizedHTMLTransformAddBeforeEndTagIntegration(t *testing.T) {
	htmlContent := `<html>
<head>
<style></style>
</head>
<body>
content
</body>
</html>`

	expectedOutput := `<html>
<head>
<style></style>
</head>
<body>
content
<!-- Test --></body>
</html>`

	// Test with add_before_end_tag: true
	configJSON := `{
		"type": "optimized_html",
		"add_to_tags": [{
			"tag": "body",
			"add_before_end_tag": true,
			"content": "<!-- Test -->"
		}]
	}`

	cfg, err := NewOptimizedHTMLTransform([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	htmlCfg := cfg.(*OptimizedHTMLTransformConfig)
	require.NotNil(t, htmlCfg.tr)

	// Create a mock HTTP response
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp := &http.Response{
		Request: req,
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader(htmlContent)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// Apply the transform
	err = htmlCfg.tr.Modify(resp)
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
	assert.Equal(t, expectedOutput, output, "Optimized HTML transform should add content before closing body tag when add_before_end_tag: true")
}

func TestHTMLTransformAddBeforeEndTagFalseIntegration(t *testing.T) {
	htmlContent := `<html>
<head>
<style></style>
</head>
<body>
content
</body>
</html>`

	expectedOutput := `<html>
<head><meta name="test">
<style></style>
</head>
<body>
content
</body>
</html>`

	// Test with add_before_end_tag: false (should add after opening tag)
	configJSON := `{
		"type": "html",
		"add_to_tags": [{
			"tag": "head",
			"add_before_end_tag": false,
			"content": "<meta name=\"test\">"
		}]
	}`

	cfg, err := NewHTMLTransform([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	htmlCfg := cfg.(*HTMLTransformConfig)
	require.NotNil(t, htmlCfg.tr)

	// Create a mock HTTP response
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp := &http.Response{
		Request: req,
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader(htmlContent)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// Apply the transform
	err = htmlCfg.tr.Modify(resp)
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
	assert.Equal(t, expectedOutput, output, "HTML transform should add content after opening head tag when add_before_end_tag: false")
}

func TestOptimizedHTMLTransformAddBeforeEndTagFalseIntegration(t *testing.T) {
	htmlContent := `<html>
<head>
<style></style>
</head>
<body>
content
</body>
</html>`

	expectedOutput := `<html>
<head>
<meta name="test"><style></style>
</head>
<body>
content
</body>
</html>`

	// Test with add_before_end_tag: false (should add after opening tag)
	configJSON := `{
		"type": "optimized_html",
		"add_to_tags": [{
			"tag": "head",
			"add_before_end_tag": false,
			"content": "<meta name=\"test\">"
		}]
	}`

	cfg, err := NewOptimizedHTMLTransform([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	htmlCfg := cfg.(*OptimizedHTMLTransformConfig)
	require.NotNil(t, htmlCfg.tr)

	// Create a mock HTTP response
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp := &http.Response{
		Request: req,
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader(htmlContent)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// Apply the transform
	err = htmlCfg.tr.Modify(resp)
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
	assert.Equal(t, expectedOutput, output, "Optimized HTML transform should add content after opening head tag when add_before_end_tag: false")
}

