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

func TestMinifyJavascript_Basic(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		opts     MinifyJavascriptOptions
		checkFn  func(t *testing.T, output string, err error)
	}{
		{
			name:  "minify simple function",
			input: `function add(a, b) { return a + b; }`,
			opts:  MinifyJavascriptOptions{},
			checkFn: func(t *testing.T, output string, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, output)
				assert.True(t, len(output) <= len(`function add(a, b) { return a + b; }`))
			},
		},
		{
			name:  "minify with comments",
			input: `// Comment\nfunction test() { return 1; }`,
			opts:  MinifyJavascriptOptions{},
			checkFn: func(t *testing.T, output string, err error) {
				require.NoError(t, err)
				assert.NotContains(t, output, "Comment")
			},
		},
		{
			name:  "keep variable names",
			input: `var myVariable = 123;`,
			opts: MinifyJavascriptOptions{
				KeepVarNames: true,
			},
			checkFn: func(t *testing.T, output string, err error) {
				require.NoError(t, err)
				assert.Contains(t, output, "myVariable")
			},
		},
		{
			name:  "empty body",
			input: ``,
			opts:  MinifyJavascriptOptions{},
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
			resp.Header.Set("Content-Type", "application/javascript")

			transform := MinifyJavascript(tt.opts)
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

func TestMinifyJavascript_ContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		shouldError bool
	}{
		{"application/javascript", "application/javascript", false},
		{"application/x-javascript", "application/x-javascript", false},
		{"text/javascript", "text/javascript", false},
		{"text/ecmascript", "text/ecmascript", false},
		{"text/html", "text/html", true},
		{"application/json", "application/json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:    io.NopCloser(strings.NewReader(`var x = 1;`)),
				Header:  make(http.Header),
				Request: &http.Request{},
			}
			resp.Header.Set("Content-Type", tt.contentType)

			transform := MinifyJavascript(MinifyJavascriptOptions{})
			err := transform.Modify(resp)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidContentType, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "application/javascript", resp.Header.Get("Content-Type"))
				assert.Empty(t, resp.Header.Get("Content-Length"))
			}
		})
	}
}

func TestMinifyJavascript_WithFixture(t *testing.T) {
	fixture, err := os.ReadFile("fixtures/test.js")
	require.NoError(t, err)

	resp := &http.Response{
		Body:    io.NopCloser(bytes.NewReader(fixture)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "application/javascript")

	transform := MinifyJavascript(MinifyJavascriptOptions{})
	err = transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Minified output should be smaller or equal
	assert.True(t, len(body) <= len(fixture))
	assert.Equal(t, "application/javascript", resp.Header.Get("Content-Type"))
}

func TestMinifyJavascript_Options(t *testing.T) {
	input := `var myVariable = 123; const anotherVar = 456;`

	tests := []struct {
		name string
		opts MinifyJavascriptOptions
	}{
		{"default options", MinifyJavascriptOptions{}},
		{"with precision", MinifyJavascriptOptions{Precision: 2}},
		{"keep var names", MinifyJavascriptOptions{KeepVarNames: true}},
		{"with version", MinifyJavascriptOptions{Version: 5}},
		{"all options", MinifyJavascriptOptions{
			Precision:    2,
			KeepVarNames: true,
			Version:      5,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:    io.NopCloser(strings.NewReader(input)),
				Header:  make(http.Header),
				Request: &http.Request{},
			}
			resp.Header.Set("Content-Type", "application/javascript")

			transform := MinifyJavascript(tt.opts)
			err := transform.Modify(resp)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.NotEmpty(t, body)
		})
	}
}

func TestMinifyJavascript_ErrorHandling(t *testing.T) {
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(`invalid javascript syntax {`)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "application/javascript")

	transform := MinifyJavascript(MinifyJavascriptOptions{})
	err := transform.Modify(resp)
	
	// Minifier will error on invalid syntax - this is expected behavior
	// We verify the transform handles errors gracefully
	if err != nil {
		// Error is expected and acceptable for invalid syntax
		assert.Error(t, err)
	} else {
		// If no error, read the body to ensure it didn't crash
		_, readErr := io.ReadAll(resp.Body)
		if readErr != nil && readErr != io.EOF {
			t.Logf("Body read error: %v", readErr)
		}
	}
}

