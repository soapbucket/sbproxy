// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
)

// MinifyCSSOptions configures the behavior of CSS minification
type MinifyCSSOptions struct {
	// Precision is the number of significant digits to preserve for numbers
	Precision int
	// Inline controls whether to inline styles
	Inline bool
	// Version specifies the CSS version for output (0 for automatic)
	Version int
}

// MinifyCSS creates a Transformer function that minifies CSS content.
// It can be passed to apply CSS minification to HTTP responses.
//
// Options:
//   - Precision: Number of significant digits to preserve (0 for default)
//   - Inline: When true, enables inline style processing
//   - Version: CSS version for output (0 for automatic detection)
//   - KeepCSS2: Deprecated, use Version = 2 instead
//
// Example usage:
//
//	transform := MinifyCSS(MinifyCSSOptions{
//	    Precision: 0,
//	    Inline:    false,
//	    Version:   0,
//	})
func MinifyCSS(options MinifyCSSOptions) Transformer {
	return Func(func(resp *http.Response) error {
		return minifyCSS(resp, options)
	})
}

func minifyCSS(resp *http.Response, opts MinifyCSSOptions) error {
	logger := slog.With("url", resp.Request.URL)

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		logger.Error("Failed to parse content type", "error", err)
		return err
	}

	// Check if content type is CSS
	// Accept text/css and application/css
	isCSS := strings.EqualFold(contentType, "text/css") ||
		strings.EqualFold(contentType, "application/css")

	if !isCSS {
		logger.Debug("Skipping CSS minification for content type", "content_type", contentType)
		return ErrInvalidContentType
	}

	logger.Debug("Applying CSS minification")

	// Create a pipe for streaming minification
	pr, pw := io.Pipe()

	// Create a minifier instance
	m := minify.New()

	// Create and configure the CSS minifier
	cssMinifier := &css.Minifier{
		Precision: opts.Precision,
		Inline:    opts.Inline,
		Version:   opts.Version,
	}

	// Register the CSS minifier
	m.AddFunc("text/css", cssMinifier.Minify)

	// Start minification in a goroutine
	originalBody := resp.Body
	go func() {
		defer originalBody.Close()
		defer pw.Close()

		// Minify from the original body directly to the pipe writer
		if err := m.Minify("text/css", pw, originalBody); err != nil {
			logger.Error("Failed to minify CSS", "error", err)
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
	resp.Header.Set("Content-Type", "text/css")

	return nil
}
