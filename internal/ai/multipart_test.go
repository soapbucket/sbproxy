package ai

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func TestExtractMultipartMetadata(t *testing.T) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("model", "whisper-1")
	writer.WriteField("language", "en")
	writer.WriteField("response_format", "json")

	// Create a fake file part.
	part, err := writer.CreateFormFile("file", "audio.mp3")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	fileData := strings.Repeat("x", 1024) // 1KB fake audio
	part.Write([]byte(fileData))
	writer.Close()

	req, err := http.NewRequest("POST", "/v1/audio/transcriptions", &buf)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	meta, err := ExtractMultipartMetadata(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if meta.Model != "whisper-1" {
		t.Errorf("Model = %q, want whisper-1", meta.Model)
	}
	if meta.Language != "en" {
		t.Errorf("Language = %q, want en", meta.Language)
	}
	if meta.Format != "json" {
		t.Errorf("Format = %q, want json", meta.Format)
	}
	if !meta.HasFile {
		t.Error("expected HasFile to be true")
	}
	if meta.FileSize != 1024 {
		t.Errorf("FileSize = %d, want 1024", meta.FileSize)
	}
	if meta.FileName != "audio.mp3" {
		t.Errorf("FileName = %q, want audio.mp3", meta.FileName)
	}
}

func TestExtractMultipartMetadata_NoFile(t *testing.T) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("model", "whisper-1")
	writer.Close()

	req, err := http.NewRequest("POST", "/v1/audio/transcriptions", &buf)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	meta, err := ExtractMultipartMetadata(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if meta.Model != "whisper-1" {
		t.Errorf("Model = %q, want whisper-1", meta.Model)
	}
	if meta.HasFile {
		t.Error("expected HasFile to be false")
	}
	if meta.FileSize != 0 {
		t.Errorf("FileSize = %d, want 0", meta.FileSize)
	}
}

func TestExtractMultipartMetadata_LargeFile(t *testing.T) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("model", "whisper-1")

	part, err := writer.CreateFormFile("file", "large_audio.wav")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	// Write 100KB of data.
	largeData := make([]byte, 100*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	part.Write(largeData)
	writer.Close()

	req, err := http.NewRequest("POST", "/v1/audio/transcriptions", &buf)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	meta, err := ExtractMultipartMetadata(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !meta.HasFile {
		t.Error("expected HasFile to be true")
	}
	if meta.FileSize != 100*1024 {
		t.Errorf("FileSize = %d, want %d", meta.FileSize, 100*1024)
	}
	if meta.FileName != "large_audio.wav" {
		t.Errorf("FileName = %q, want large_audio.wav", meta.FileName)
	}
}

func TestExtractMultipartMetadata_InvalidContentType(t *testing.T) {
	req, _ := http.NewRequest("POST", "/v1/audio/transcriptions", strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "application/json")

	_, err := ExtractMultipartMetadata(req)
	if err == nil {
		t.Error("expected error for non-multipart content type")
	}
}

func TestExtractMultipartMetadata_MissingContentType(t *testing.T) {
	req, _ := http.NewRequest("POST", "/v1/audio/transcriptions", strings.NewReader(""))

	_, err := ExtractMultipartMetadata(req)
	if err == nil {
		t.Error("expected error for missing content type")
	}
}

func TestForwardMultipart(t *testing.T) {
	// Test with empty body should error.
	_, err := ForwardMultipart(nil, nil, "", "http://example.com", nil)
	if err == nil {
		t.Error("expected error for empty body")
	}
}
