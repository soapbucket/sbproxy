package transformer

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

// TestAddToTagPrependLogic tests the prepend logic for add_to_tags feature
// This test verifies that:
// - prepend: false adds content after the opening tag (beginning of tag content)
// - prepend: true adds content before the closing tag (end of tag content)
func TestAddToTagPrependLogic(t *testing.T) {
	// Basic HTML with head and body tags
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

	// Create transformer with both add_to_tags configurations
	reader := strings.NewReader(htmlContent)
	transformer := &HTMLTransformer{
		tokenizer: html.NewTokenizer(io.NopCloser(reader)),
		buffer:    &bytes.Buffer{},
		closer:    io.NopCloser(reader),
		fns: []ModifyFn{
			// prepend: false for head - should add after <head> tag
			AddToTagPrepend("head", "<meta name=\"proxy\" content=\"enabled\">", false),
			// prepend: true for body - should add before </body> tag
			AddToTagPrepend("body", "<!-- Proxy injected content -->", true),
		},
	}

	var result bytes.Buffer
	buffer := make([]byte, 1024)
	for {
		n, err := transformer.Read(buffer)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		result.Write(buffer[:n])
	}

	output := result.String()
	assert.Equal(t, expectedOutput, output, "Content should be added correctly: meta tag after <head>, comment before </body>")
}

// TestAddToTagPrependHeadOnly tests prepend: false for head tag
func TestAddToTagPrependHeadOnly(t *testing.T) {
	htmlContent := `<html>
<head>
<style></style>
</head>
<body>
content
</body>
</html>`

	expectedOutput := `<html>
<head><meta name="proxy" content="enabled">
<style></style>
</head>
<body>
content
</body>
</html>`

	reader := strings.NewReader(htmlContent)
	transformer := &HTMLTransformer{
		tokenizer: html.NewTokenizer(io.NopCloser(reader)),
		buffer:    &bytes.Buffer{},
		closer:    io.NopCloser(reader),
		fns: []ModifyFn{
			AddToTagPrepend("head", "<meta name=\"proxy\" content=\"enabled\">", false),
		},
	}

	var result bytes.Buffer
	buffer := make([]byte, 1024)
	for {
		n, err := transformer.Read(buffer)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		result.Write(buffer[:n])
	}

	output := result.String()
	assert.Equal(t, expectedOutput, output, "Meta tag should be added after <head> tag")
}

// TestAddToTagPrependBodyOnly tests prepend: true for body tag
func TestAddToTagPrependBodyOnly(t *testing.T) {
	htmlContent := `<html>
<head>
</head>
<body>
asdf
</body>
</html>`

	expectedOutput := `<html>
<head>
</head>
<body>
asdf
<!-- Proxy injected content --></body>
</html>`

	reader := strings.NewReader(htmlContent)
	transformer := &HTMLTransformer{
		tokenizer: html.NewTokenizer(io.NopCloser(reader)),
		buffer:    &bytes.Buffer{},
		closer:    io.NopCloser(reader),
		fns: []ModifyFn{
			AddToTagPrepend("body", "<!-- Proxy injected content -->", true),
		},
	}

	var result bytes.Buffer
	buffer := make([]byte, 1024)
	for {
		n, err := transformer.Read(buffer)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		result.Write(buffer[:n])
	}

	output := result.String()
	assert.Equal(t, expectedOutput, output, "Comment should be added before </body> tag")
}

// TestAddToTagPrependHeadWithoutClosingTag tests head tag without explicit closing tag
func TestAddToTagPrependHeadWithoutClosingTag(t *testing.T) {
	htmlContent := `<html>
<head>
<style></style>
<body>
content
</body>
</html>`

	expectedOutput := `<html>
<head><meta name="proxy" content="enabled">
<style></style>
<body>
content
</body>
</html>`

	reader := strings.NewReader(htmlContent)
	transformer := &HTMLTransformer{
		tokenizer: html.NewTokenizer(io.NopCloser(reader)),
		buffer:    &bytes.Buffer{},
		closer:    io.NopCloser(reader),
		fns: []ModifyFn{
			AddToTagPrepend("head", "<meta name=\"proxy\" content=\"enabled\">", false),
		},
	}

	var result bytes.Buffer
	buffer := make([]byte, 1024)
	for {
		n, err := transformer.Read(buffer)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		result.Write(buffer[:n])
	}

	output := result.String()
	assert.Equal(t, expectedOutput, output, "Meta tag should be added after <head> tag even without explicit </head>")
}

