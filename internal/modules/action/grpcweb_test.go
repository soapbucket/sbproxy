package action

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsGRPCWebRequest(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{"grpc-web", "application/grpc-web", true},
		{"grpc-web+proto", "application/grpc-web+proto", true},
		{"grpc-web-text", "application/grpc-web-text", true},
		{"grpc-web-text+proto", "application/grpc-web-text+proto", true},
		{"standard grpc", "application/grpc", false},
		{"json", "application/json", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.contentType != "" {
				r.Header.Set("Content-Type", tt.contentType)
			}
			if got := IsGRPCWebRequest(r); got != tt.want {
				t.Errorf("IsGRPCWebRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTranscodeGRPCWebRequest_Binary(t *testing.T) {
	body := []byte("binary-grpc-data")
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/grpc-web+proto")

	err := TranscodeGRPCWebRequest(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/grpc+proto" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/grpc+proto")
	}

	// Body should be unchanged for binary variant.
	readBody, _ := io.ReadAll(r.Body)
	if string(readBody) != string(body) {
		t.Errorf("body = %q, want %q", readBody, body)
	}
}

func TestTranscodeGRPCWebRequest_Text(t *testing.T) {
	// Base64 encode some test data.
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("dGVzdA=="))) // "test" in base64
	r.Header.Set("Content-Type", "application/grpc-web-text")

	err := TranscodeGRPCWebRequest(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/grpc" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/grpc")
	}

	readBody, _ := io.ReadAll(r.Body)
	if string(readBody) != "test" {
		t.Errorf("decoded body = %q, want %q", readBody, "test")
	}
}

func TestTranscodeGRPCWebRequest_NilBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Content-Type", "application/grpc-web")
	r.Body = nil

	err := TranscodeGRPCWebRequest(r)
	if err != nil {
		t.Fatalf("unexpected error with nil body: %v", err)
	}
}

func TestTranscodeGRPCWebResponse_NilResponse(t *testing.T) {
	w := httptest.NewRecorder()
	err := TranscodeGRPCWebResponse(w, nil, false)
	if err == nil {
		t.Fatal("expected error for nil response")
	}
}

func TestTranscodeGRPCWebResponse_Binary(t *testing.T) {
	body := []byte("response-data")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/grpc+proto"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Trailer:    http.Header{"Grpc-Status": {"0"}},
	}

	w := httptest.NewRecorder()
	err := TranscodeGRPCWebResponse(w, resp, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/grpc-web+proto" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/grpc-web+proto")
	}

	result := w.Body.Bytes()
	// Should contain body + trailer frame.
	if len(result) <= len(body) {
		t.Error("expected body + trailer frame, got only body or less")
	}
}

func TestTranscodeGRPCWebResponse_Text(t *testing.T) {
	body := []byte("response-data")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/grpc"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	w := httptest.NewRecorder()
	err := TranscodeGRPCWebResponse(w, resp, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/grpc-web-text" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/grpc-web-text")
	}

	// Output should be base64 encoded.
	result := w.Body.String()
	if len(result) == 0 {
		t.Error("expected non-empty base64 response")
	}
}
