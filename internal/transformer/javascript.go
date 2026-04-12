// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/js"
)

// MinifyJavascriptOptions configures the behavior of JavaScript minification
type MinifyJavascriptOptions struct {
	// Precision is the number of significant digits to preserve for numbers
	Precision int
	// KeepVarNames preserves variable names when set to true
	KeepVarNames bool
	// Version specifies the ECMAScript version for output (0 for automatic)
	Version int
}

// MinifyJavascript creates a Transformer function that minifies JavaScript content.
// It can be passed to apply JavaScript minification to HTTP responses.
//
// Options:
//   - Precision: Number of significant digits to preserve (0 for default)
//   - KeepVarNames: When true, preserves variable names during minification
//   - Version: ECMAScript version for output (0 for automatic detection)
//
// Example usage:
//
//	transform := MinifyJavascript(MinifyJavascriptOptions{
//	    Precision:    0,
//	    KeepVarNames: false,
//	    Version:      0,
//	})
func MinifyJavascript(options MinifyJavascriptOptions) Transformer {
	return Func(func(resp *http.Response) error {
		return minifyJavascript(resp, options)
	})
}

func minifyJavascript(resp *http.Response, opts MinifyJavascriptOptions) error {
	logger := slog.With("url", resp.Request.URL)

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		logger.Error("Failed to parse content type", "error", err)
		return err
	}

	// Check if content type is JavaScript
	// Accept application/javascript, application/x-javascript, text/javascript, and text/ecmascript
	isJavaScript := strings.EqualFold(contentType, "application/javascript") ||
		strings.EqualFold(contentType, "application/x-javascript") ||
		strings.EqualFold(contentType, "text/javascript") ||
		strings.EqualFold(contentType, "text/ecmascript")

	if !isJavaScript {
		logger.Debug("Skipping JavaScript minification for content type", "content_type", contentType)
		return ErrInvalidContentType
	}

	logger.Debug("Applying JavaScript minification")

	// Create a pipe for streaming minification
	pr, pw := io.Pipe()

	// Create a minifier instance
	m := minify.New()

	// Create and configure the JS minifier
	jsMinifier := &js.Minifier{
		Precision:    opts.Precision,
		KeepVarNames: opts.KeepVarNames,
		Version:      opts.Version,
	}

	// Register the JavaScript minifier
	m.AddFunc("application/javascript", jsMinifier.Minify)

	// Start minification in a goroutine
	originalBody := resp.Body
	go func() {
		defer originalBody.Close()
		defer pw.Close()

		// Minify from the original body directly to the pipe writer
		if err := m.Minify("application/javascript", pw, originalBody); err != nil {
			logger.Error("Failed to minify JavaScript", "error", err)
			pw.CloseWithError(err)
			return
		}
	}()

	// Replace response body with pipe reader
	resp.Body = pr

	// Remove Content-Length header since we don't know the final size yet
	// The minified output will be streamed
	resp.Header.Del("Content-Length")

	// Ensure Content-Type is set correctly
	resp.Header.Set("Content-Type", "application/javascript")

	return nil
}
