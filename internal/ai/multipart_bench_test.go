package ai

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func BenchmarkExtractMultipartMetadata(b *testing.B) {
	// Pre-build the multipart body.
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("model", "whisper-1")
	writer.WriteField("language", "en")
	writer.WriteField("response_format", "json")
	part, err := writer.CreateFormFile("file", "audio.mp3")
	if err != nil {
		b.Fatalf("failed to create form file: %v", err)
	}
	fileData := strings.Repeat("x", 4096) // 4KB fake audio
	part.Write([]byte(fileData))
	writer.Close()

	body := buf.Bytes()
	contentType := writer.FormDataContentType()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/v1/audio/transcriptions", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		_, err := ExtractMultipartMetadata(req)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
