// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

const maxBufferSize = 3 * 1024

// ModifyFn is a function type for modify fn callbacks.
type ModifyFn func(html.Token, io.Writer) error

// ErrSkipToken is a sentinel error for skip token conditions.
var ErrSkipToken = errors.New("skip")

// Pool for HTML transformer buffers
var bufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, maxBufferSize))
	},
}

// HTMLTransformer represents a html transformer.
type HTMLTransformer struct {
	tokenizer *html.Tokenizer
	buffer    *bytes.Buffer
	closer    io.Closer
	fns       []ModifyFn

	err error
}

// Read performs the read operation on the HTMLTransformer.
func (t *HTMLTransformer) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// If we have buffered data, read from it first
	if t.buffer.Len() > 0 {
		n, err := t.buffer.Read(b)
		// Return data even if EOF, we'll get EOF on next call if needed
		if n > 0 {
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
	}

	// If we've already reached EOF and buffer is empty, return EOF
	if t.err == io.EOF {
		return 0, io.EOF
	}

	// Try to fill the buffer
	if err := t.fill(); err != nil {
		t.err = err
		// If we got EOF, check if we filled any data
		if err == io.EOF && t.buffer.Len() > 0 {
			// We have data, read it and return, EOF will be returned on next call
			return t.buffer.Read(b)
		}
		return 0, err
	}

	// Read from the newly filled buffer
	return t.buffer.Read(b)
}

// Close releases resources held by the HTMLTransformer.
func (t *HTMLTransformer) Close() error {
	// Return buffer to pool
	if t.buffer != nil {
		slog.Debug("Returning buffer to pool", "size", t.buffer.Len())
		t.buffer.Reset()
		bufferPool.Put(t.buffer)
		t.buffer = nil
	}
	return t.closer.Close()
}

func (t *HTMLTransformer) fill() error {
	processedTokens := false

	for {
		if t.buffer.Len() >= maxBufferSize {
			return nil
		}

		// exit on error
		tokenType := t.tokenizer.Next()
		if tokenType == html.ErrorToken {
			err := t.tokenizer.Err()
			// If we've processed any tokens, return success
			// The error will be returned on the next call to fill()
			if processedTokens {
				return nil
			}
			return err
		}

		processedTokens = true
		token := t.tokenizer.Token()
		data := t.tokenizer.Raw()

		// Early exit if no modification functions
		if len(t.fns) == 0 {
			t.buffer.Write(data)
			// Check if we've exceeded max buffer size after writing
			if t.buffer.Len() >= maxBufferSize {
				return nil
			}
			continue
		}

		// Apply modification functions
		var err error
		for _, fn := range t.fns {
			if err = fn(token, t.buffer); err != nil {
				break
			}
		}

		if err != nil {
			if err == ErrSkipToken {
				continue
			}
			return err
		}

		t.buffer.Write(data)
		// Check if we've exceeded max buffer size after writing
		if t.buffer.Len() >= maxBufferSize {
			return nil
		}
	}
}

// ModifyHTML performs the modify html operation.
func ModifyHTML(fns ...ModifyFn) Transformer {
	return Func(func(resp *http.Response) error {
		return modifyHTML(resp, fns...)
	})
}

func modifyHTML(resp *http.Response, fns ...ModifyFn) error {
	slog.Debug("modifyHTML for origin", "url", resp.Request.URL)

	// Skip HTML transformation for methods that should not have a response body
	// HEAD and OPTIONS requests typically don't have response bodies to transform
	if resp.Request != nil {
		method := resp.Request.Method
		if method == http.MethodHead || method == http.MethodOptions {
			slog.Debug("Skipping HTML transform for request method without response body", "method", method)
			return nil
		}
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		slog.Error("Failed to parse content type", "error", err)
		return err
	}

	if !strings.EqualFold(contentType, "text/html") {
		slog.Debug("Skipping HTML transform for content type", "content_type", contentType)
		return ErrInvalidContentType
	}

	slog.Debug("Applying HTML transform", "modification_functions", len(fns))

	// Get buffer from pool
	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()

	t := &HTMLTransformer{
		buffer:    buffer,
		tokenizer: html.NewTokenizer(resp.Body),
		closer:    resp.Body,
		fns:       fns,
	}

	resp.Body = t
	return nil
}
