package httputil

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		name        string
		sizeStr     string
		defaultSize int64
		expected    int64
	}{
		{"Empty string", "", 1024, 1024},
		{"Bytes", "1024", 512, 1024},
		{"KB lowercase", "10kb", 1024, 10 * 1024},
		{"KB uppercase", "10KB", 1024, 10 * 1024},
		{"K shorthand", "10K", 1024, 10 * 1024},
		{"MB lowercase", "10mb", 1024, 10 * 1024 * 1024},
		{"MB uppercase", "10MB", 1024, 10 * 1024 * 1024},
		{"M shorthand", "10M", 1024, 10 * 1024 * 1024},
		{"GB", "2GB", 1024, 2 * 1024 * 1024 * 1024},
		{"TB", "1TB", 1024, 1 * 1024 * 1024 * 1024 * 1024},
		{"With spaces", " 10MB ", 1024, 10 * 1024 * 1024},
		{"Invalid number", "abc", 1024, 1024},
		{"Invalid unit", "10XYZ", 1024, 1024},
		{"Decimal", "10.5MB", 1024, 10 * 1024 * 1024}, // Should truncate
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSize(tt.sizeStr, tt.defaultSize)
			if result != tt.expected {
				t.Errorf("parseSize(%q, %d) = %d, want %d", tt.sizeStr, tt.defaultSize, result, tt.expected)
			}
		})
	}
}

func TestGetStreamingThresholds(t *testing.T) {
	tests := []struct {
		name                    string
		enabled                 bool
		maxBufferedBodySize     string
		maxProcessableBodySize  string
		modifierThreshold       string
		transformThreshold      string
		signatureThreshold      string
		callbackThreshold       string
		expectedEnabled         bool
		expectedMaxBuffered     int64
		expectedMaxProcessable  int64
		expectedModifier        int64
		expectedTransform       int64
		expectedSignature       int64
		expectedCallback        int64
	}{
		{
			name:                   "All defaults",
			enabled:                false,
			maxBufferedBodySize:    "",
			expectedEnabled:        true, // Defaults to enabled if not configured
			expectedMaxBuffered:    DefaultMaxBufferedBodySize,
			expectedMaxProcessable: DefaultMaxProcessableBodySize,
			expectedModifier:       DefaultModifierThreshold,
			expectedTransform:      DefaultTransformThreshold,
			expectedSignature:      DefaultSignatureThreshold,
			expectedCallback:       DefaultCallbackThreshold,
		},
		{
			name:                   "Explicitly disabled",
			enabled:                false,
			maxBufferedBodySize:    "5MB",
			expectedEnabled:        false,
			expectedMaxBuffered:    5 * 1024 * 1024,
			expectedMaxProcessable: DefaultMaxProcessableBodySize,
		},
		{
			name:                   "Custom thresholds",
			enabled:                true,
			maxBufferedBodySize:    "5MB",
			maxProcessableBodySize: "50MB",
			modifierThreshold:      "2MB",
			transformThreshold:     "3MB",
			signatureThreshold:     "20MB",
			callbackThreshold:     "500KB",
			expectedEnabled:        true,
			expectedMaxBuffered:    5 * 1024 * 1024,
			expectedMaxProcessable: 50 * 1024 * 1024,
			expectedModifier:       2 * 1024 * 1024,
			expectedTransform:      3 * 1024 * 1024,
			expectedSignature:      20 * 1024 * 1024,
			expectedCallback:       500 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetStreamingThresholds(
				tt.enabled,
				tt.maxBufferedBodySize,
				tt.maxProcessableBodySize,
				tt.modifierThreshold,
				tt.transformThreshold,
				tt.signatureThreshold,
				tt.callbackThreshold,
			)

			if result.Enabled != tt.expectedEnabled {
				t.Errorf("Enabled = %v, want %v", result.Enabled, tt.expectedEnabled)
			}
			if tt.expectedMaxBuffered > 0 && result.MaxBufferedBodySize != tt.expectedMaxBuffered {
				t.Errorf("MaxBufferedBodySize = %d, want %d", result.MaxBufferedBodySize, tt.expectedMaxBuffered)
			}
			if tt.expectedMaxProcessable > 0 && result.MaxProcessableBodySize != tt.expectedMaxProcessable {
				t.Errorf("MaxProcessableBodySize = %d, want %d", result.MaxProcessableBodySize, tt.expectedMaxProcessable)
			}
			if tt.expectedModifier > 0 && result.ModifierThreshold != tt.expectedModifier {
				t.Errorf("ModifierThreshold = %d, want %d", result.ModifierThreshold, tt.expectedModifier)
			}
			if tt.expectedTransform > 0 && result.TransformThreshold != tt.expectedTransform {
				t.Errorf("TransformThreshold = %d, want %d", result.TransformThreshold, tt.expectedTransform)
			}
			if tt.expectedSignature > 0 && result.SignatureThreshold != tt.expectedSignature {
				t.Errorf("SignatureThreshold = %d, want %d", result.SignatureThreshold, tt.expectedSignature)
			}
			if tt.expectedCallback > 0 && result.CallbackThreshold != tt.expectedCallback {
				t.Errorf("CallbackThreshold = %d, want %d", result.CallbackThreshold, tt.expectedCallback)
			}
		})
	}
}

func TestSizeTracker(t *testing.T) {
	t.Run("Read within threshold", func(t *testing.T) {
		data := make([]byte, 1000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		reader := io.NopCloser(bytes.NewReader(data))
		tracker := NewSizeTracker(reader, 2000)

		buf := make([]byte, 500)
		n, err := tracker.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("Read error: %v", err)
		}
		if n != 500 {
			t.Errorf("Read %d bytes, want 500", n)
		}
		if tracker.BytesRead() != 500 {
			t.Errorf("BytesRead() = %d, want 500", tracker.BytesRead())
		}
		if tracker.Exceeded() {
			t.Error("Exceeded() = true, want false")
		}
	})

	t.Run("Read exceeds threshold", func(t *testing.T) {
		data := make([]byte, 5000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		reader := io.NopCloser(bytes.NewReader(data))
		tracker := NewSizeTracker(reader, 2000)

		buf := make([]byte, 3000)
		n, err := tracker.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("Read error: %v", err)
		}
		if n != 3000 {
			t.Errorf("Read %d bytes, want 3000", n)
		}
		if tracker.BytesRead() != 3000 {
			t.Errorf("BytesRead() = %d, want 3000", tracker.BytesRead())
		}
		if !tracker.Exceeded() {
			t.Error("Exceeded() = false, want true")
		}
	})

	t.Run("Read exactly at threshold", func(t *testing.T) {
		data := make([]byte, 2000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		reader := io.NopCloser(bytes.NewReader(data))
		tracker := NewSizeTracker(reader, 2000)

		buf := make([]byte, 2000)
		n, err := tracker.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("Read error: %v", err)
		}
		if n != 2000 {
			t.Errorf("Read %d bytes, want 2000", n)
		}
		if tracker.BytesRead() != 2000 {
			t.Errorf("BytesRead() = %d, want 2000", tracker.BytesRead())
		}
		// Should not exceed if exactly at threshold
		if tracker.Exceeded() {
			t.Error("Exceeded() = true, want false (exactly at threshold)")
		}
	})

	t.Run("Multiple reads", func(t *testing.T) {
		data := make([]byte, 5000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		reader := io.NopCloser(bytes.NewReader(data))
		tracker := NewSizeTracker(reader, 2000)

		// First read - within threshold
		buf1 := make([]byte, 1000)
		n1, err := tracker.Read(buf1)
		if err != nil && err != io.EOF {
			t.Fatalf("Read error: %v", err)
		}
		if n1 != 1000 {
			t.Errorf("First read: got %d bytes, want 1000", n1)
		}
		if tracker.Exceeded() {
			t.Error("Should not exceed after first read")
		}

		// Second read - exceeds threshold
		buf2 := make([]byte, 2000)
		n2, err := tracker.Read(buf2)
		if err != nil && err != io.EOF {
			t.Fatalf("Read error: %v", err)
		}
		if n2 != 2000 {
			t.Errorf("Second read: got %d bytes, want 2000", n2)
		}
		if !tracker.Exceeded() {
			t.Error("Should exceed after second read")
		}
		if tracker.BytesRead() != 3000 {
			t.Errorf("BytesRead() = %d, want 3000", tracker.BytesRead())
		}
	})

	t.Run("Original reader access", func(t *testing.T) {
		data := make([]byte, 1000)
		originalReader := io.NopCloser(bytes.NewReader(data))
		tracker := NewSizeTracker(originalReader, 2000)

		if tracker.Original() != originalReader {
			t.Error("Original() did not return the original reader")
		}
	})

	t.Run("Close", func(t *testing.T) {
		data := make([]byte, 1000)
		reader := io.NopCloser(bytes.NewReader(data))
		tracker := NewSizeTracker(reader, 2000)

		if err := tracker.Close(); err != nil {
			t.Errorf("Close() error: %v", err)
		}
	})
}

func TestShouldStream(t *testing.T) {
	tests := []struct {
		name        string
		contentLen  int64
		threshold   int64
		shouldStream bool
	}{
		{"Small body", 1000, 10000, false},
		{"Exact threshold", 10000, 10000, false},
		{"Large body", 20000, 10000, true},
		{"Zero content length", 0, 10000, false},
		{"Negative content length", -1, 10000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				ContentLength: tt.contentLen,
			}
			result := ShouldStream(resp, tt.threshold)
			if result != tt.shouldStream {
				t.Errorf("ShouldStream(contentLen=%d, threshold=%d) = %v, want %v",
					tt.contentLen, tt.threshold, result, tt.shouldStream)
			}
		})
	}
}

func TestCheckBodySize(t *testing.T) {
	tests := []struct {
		name        string
		contentLen  int64
		maxSize     int64
		expectError bool
	}{
		{"Within limit", 1000, 10000, false},
		{"At limit", 10000, 10000, false},
		{"Exceeds limit", 20000, 10000, true},
		{"Zero content length", 0, 10000, false},
		{"Negative content length", -1, 10000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckBodySize(tt.contentLen, tt.maxSize)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestWrapResponseWithSizeLimit(t *testing.T) {
	t.Run("Small body - no wrapping", func(t *testing.T) {
		data := make([]byte, 1000)
		resp := &http.Response{
			ContentLength: 1000,
			Body:          io.NopCloser(bytes.NewReader(data)),
		}

		wrapped := WrapResponseWithSizeLimit(resp, 10000)
		if wrapped == nil {
			t.Fatal("WrapResponseWithSizeLimit returned nil")
		}

		// Should not wrap if under limit
		if wrapped.Body == nil {
			t.Error("Body should not be nil")
		}
	})

	t.Run("Large body - wraps with limit", func(t *testing.T) {
		data := make([]byte, 20000)
		resp := &http.Response{
			ContentLength: 20000,
			Body:          io.NopCloser(bytes.NewReader(data)),
		}

		wrapped := WrapResponseWithSizeLimit(resp, 10000)
		if wrapped == nil {
			t.Fatal("WrapResponseWithSizeLimit returned nil")
		}

		// Should wrap with MaxBytesReader
		if wrapped.Body == nil {
			t.Error("Body should not be nil")
		}

		// Try to read more than limit - should fail
		buf := make([]byte, 15000)
		_, err := wrapped.Body.Read(buf)
		if err == nil {
			t.Error("Expected error when reading beyond limit")
		}
	})

	t.Run("Nil response", func(t *testing.T) {
		result := WrapResponseWithSizeLimit(nil, 10000)
		if result != nil {
			t.Error("Expected nil for nil response")
		}
	})

	t.Run("Nil body", func(t *testing.T) {
		resp := &http.Response{
			ContentLength: 1000,
			Body:          nil,
		}
		result := WrapResponseWithSizeLimit(resp, 10000)
		if result == nil {
			t.Fatal("WrapResponseWithSizeLimit returned nil")
		}
		if result.Body != nil {
			t.Error("Body should remain nil")
		}
	})
}

