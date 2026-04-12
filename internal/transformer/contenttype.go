// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"golang.org/x/net/html/charset"
)

const (
	utf8charset    = "utf-8"
	charsetKey     = "charset"
	contentTypeKey = "Content-Type"
)

// ErrInvalidContentType is a sentinel error for invalid content type conditions.
var ErrInvalidContentType = errors.New("transformer: invalid content type")

// FixContentType performs the fix content type operation.
func FixContentType() Transformer {
	return Func(fixContentType)
}

func fixContentType(resp *http.Response) error {
	slog.Debug("fixContentType for origin", "url", resp.Request.URL)

	// Create a buffered reader from the body (which may already be decompressed by FixEncoding)
	// This allows us to peek at the content without consuming it
	rdr := bufio.NewReader(resp.Body)

	rawContentType := resp.Header.Get(contentTypeKey)
	if rawContentType == "" {
		// Empty or missing Content-Type: detect from body
		sample, err := rdr.Peek(512)
		if err != nil && err != io.EOF {
			return err
		}
		detectedType := http.DetectContentType(sample)
		resp.Header.Set(contentTypeKey, detectedType)
		rawContentType = detectedType
		slog.Debug("detected missing content type", "content_type", detectedType)
	}

	contentType, params, err := mime.ParseMediaType(rawContentType)
	if err != nil {
		return err
	}
	slog.Debug("content type parsed", "content_type", contentType, "params", params)

	if !strings.HasPrefix(contentType, "text/") && contentType != "application/json" && contentType != "application/javascript" {
		// For generic content types like application/octet-stream, try to detect the actual type
		if contentType == "application/octet-stream" {
			sample, err := rdr.Peek(512)
			if err != nil && err != io.EOF {
				return err
			}
			detectedType := http.DetectContentType(sample)
			slog.Debug("detected content type", "detected_type", detectedType)
			resp.Header.Set(contentTypeKey, detectedType)
		} else {
			slog.Debug("skipping content type", "content_type", contentType)
		}
		// Wrap the buffered reader to preserve the peeked data
		resp.Body = NewTransformReader(rdr, resp.Body)
		return nil
	}

	charSet := params[charsetKey]

	// Peek at content to determine charset if needed (before wrapping body)
	var sample []byte
	if charSet == "" || charSet != utf8charset {
		var err error
		sample, err = rdr.Peek(1024)
		if err != nil && err != io.EOF {
			return err
		}

		if charSet == "" {
			_, charSet, _ = charset.DetermineEncoding(sample, contentType)
			slog.Debug("determined charset", "charset", charSet)
		}
	}

	// Wrap the buffered reader to preserve any peeked data
	resp.Body = NewTransformReader(rdr, resp.Body)

	// Convert charset to UTF-8 if needed
	if charSet != utf8charset {
		reader, err := charset.NewReaderLabel(charSet, resp.Body)
		if err != nil {
			return err
		}

		// Read the entire body and convert to UTF-8
		// This ensures the stream is fully converted to plain text for processing
		// The body at this point is already decompressed (if it was compressed) by FixEncoding()
		// So we're converting from the source charset to UTF-8 plain text
		buffer := make([]byte, 1024)
		cleaned := &bytes.Buffer{}
		n, err := io.CopyBuffer(cleaned, reader, buffer)
		if err != nil {
			return err
		}
		resp.Body.Close()

		// Replace body with UTF-8 converted content (now fully in memory as plain text)
		// This ensures downstream transforms receive plain text UTF-8 content
		resp.Body = io.NopCloser(cleaned)
		resp.ContentLength = int64(cleaned.Len())
		slog.Debug("converted charset to UTF-8", "original_charset", charSet, "size", n, "utf8_size", cleaned.Len())
	}

	// Ensure Content-Type header includes charset=utf-8
	contentType = contentType + "; charset=utf-8"
	resp.Header.Set(contentTypeKey, contentType)

	return nil
}
