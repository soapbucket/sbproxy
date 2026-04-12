package transformer

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMinifyCSS_Basic(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		opts    MinifyCSSOptions
		checkFn func(t *testing.T, output string, err error)
	}{
		{
			name:  "minify simple CSS",
			input: `body { margin: 0; padding: 20px; }`,
			opts:  MinifyCSSOptions{},
			checkFn: func(t *testing.T, output string, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, output)
				assert.True(t, len(output) <= len(`body { margin: 0; padding: 20px; }`))
			},
		},
		{
			name:  "minify with comments",
			input: `/* Comment */ body { color: red; }`,
			opts:  MinifyCSSOptions{},
			checkFn: func(t *testing.T, output string, err error) {
				require.NoError(t, err)
				assert.NotContains(t, output, "Comment")
			},
		},
		{
			name: "minify with whitespace",
			input: `body {
    margin: 0;
    padding: 20px;
}`,
			opts: MinifyCSSOptions{},
			checkFn: func(t *testing.T, output string, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, output)
			},
		},
		{
			name:  "empty body",
			input: ``,
			opts:  MinifyCSSOptions{},
			checkFn: func(t *testing.T, output string, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:    io.NopCloser(strings.NewReader(tt.input)),
				Header:  make(http.Header),
				Request: &http.Request{},
			}
			resp.Header.Set("Content-Type", "text/css")

			transform := MinifyCSS(tt.opts)
			err := transform.Modify(resp)

			var output string
			if err == nil {
				body, readErr := io.ReadAll(resp.Body)
				require.NoError(t, readErr)
				output = string(body)
			}

			tt.checkFn(t, output, err)
		})
	}
}

func TestMinifyCSS_ContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		shouldError bool
	}{
		{"text/css", "text/css", false},
		{"application/css", "application/css", false},
		{"text/html", "text/html", true},
		{"application/json", "application/json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:    io.NopCloser(strings.NewReader(`body { color: red; }`)),
				Header:  make(http.Header),
				Request: &http.Request{},
			}
			resp.Header.Set("Content-Type", tt.contentType)

			transform := MinifyCSS(MinifyCSSOptions{})
			err := transform.Modify(resp)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidContentType, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "text/css", resp.Header.Get("Content-Type"))
				assert.Empty(t, resp.Header.Get("Content-Length"))
			}
		})
	}
}

func TestMinifyCSS_WithFixture(t *testing.T) {
	fixture, err := os.ReadFile("fixtures/test.css")
	require.NoError(t, err)

	resp := &http.Response{
		Body:    io.NopCloser(bytes.NewReader(fixture)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/css")

	transform := MinifyCSS(MinifyCSSOptions{})
	err = transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Minified output should be smaller or equal
	assert.True(t, len(body) <= len(fixture))
	assert.Equal(t, "text/css", resp.Header.Get("Content-Type"))
}

func TestMinifyCSS_Options(t *testing.T) {
	input := `body { margin: 10.5px; padding: 20.3px; }`

	tests := []struct {
		name string
		opts MinifyCSSOptions
	}{
		{"default options", MinifyCSSOptions{}},
		{"with precision", MinifyCSSOptions{Precision: 2}},
		{"with inline", MinifyCSSOptions{Inline: true}},
		{"with version", MinifyCSSOptions{Version: 3}},
		{"all options", MinifyCSSOptions{
			Precision: 2,
			Inline:    true,
			Version:   3,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:    io.NopCloser(strings.NewReader(input)),
				Header:  make(http.Header),
				Request: &http.Request{},
			}
			resp.Header.Set("Content-Type", "text/css")

			transform := MinifyCSS(tt.opts)
			err := transform.Modify(resp)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.NotEmpty(t, body)
		})
	}
}
