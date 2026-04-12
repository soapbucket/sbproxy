// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
)

// MultipartMetadata holds routing-relevant fields extracted from a multipart form request
// without buffering the file data itself.
type MultipartMetadata struct {
	Model    string
	Language string
	Format   string
	HasFile  bool
	FileSize int64
	FileName string
}

// ExtractMultipartMetadata reads routing-relevant fields from multipart form data
// without buffering file contents. The file part is counted for size but not stored.
// The original request body should be preserved (caller should buffer it if needed for forwarding).
func ExtractMultipartMetadata(r *http.Request) (*MultipartMetadata, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return nil, fmt.Errorf("missing Content-Type header")
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("invalid Content-Type: %w", err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return nil, fmt.Errorf("expected multipart content type, got %q", mediaType)
	}

	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("missing boundary in Content-Type")
	}

	meta := &MultipartMetadata{}

	reader := multipart.NewReader(r.Body, boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading multipart: %w", err)
		}

		switch part.FormName() {
		case "model":
			data, _ := io.ReadAll(part)
			meta.Model = strings.TrimSpace(string(data))
		case "language":
			data, _ := io.ReadAll(part)
			meta.Language = strings.TrimSpace(string(data))
		case "response_format":
			data, _ := io.ReadAll(part)
			meta.Format = strings.TrimSpace(string(data))
		case "file":
			meta.HasFile = true
			meta.FileName = part.FileName()
			// Count size without storing data.
			n, _ := io.Copy(io.Discard, part)
			meta.FileSize = n
		default:
			// Drain unknown parts so the reader can advance.
			_, _ = io.Copy(io.Discard, part)
		}
		part.Close()
	}

	return meta, nil
}

// ForwardMultipart forwards a multipart request to an upstream provider URL.
// It re-sends the original request body with injected authentication headers.
// The caller must buffer the request body before calling ExtractMultipartMetadata
// if both operations are needed, since the body is consumed once.
func ForwardMultipart(ctx context.Context, body []byte, contentType string, upstreamURL string, headers map[string]string) (*http.Response, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty request body")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create upstream request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}

	return resp, nil
}
