package ai

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectFormat_OpenAI(t *testing.T) {
	tests := []struct {
		path string
		want APIFormat
	}{
		{"/v1/chat/completions", FormatOpenAI},
		{"v1/chat/completions", FormatOpenAI},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://localhost"+tt.path, nil)
			got := DetectFormat(req)
			if got != tt.want {
				t.Errorf("DetectFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectFormat_Anthropic(t *testing.T) {
	tests := []struct {
		path string
		want APIFormat
	}{
		{"/v1/messages", FormatAnthropic},
		{"v1/messages", FormatAnthropic},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://localhost"+tt.path, nil)
			got := DetectFormat(req)
			if got != tt.want {
				t.Errorf("DetectFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectFormat_HeaderOverride(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		header     string
		wantFormat APIFormat
	}{
		{
			name:       "anthropic header on openai path",
			path:       "/v1/chat/completions",
			header:     "anthropic",
			wantFormat: FormatAnthropic,
		},
		{
			name:       "openai header on anthropic path",
			path:       "/v1/messages",
			header:     "openai",
			wantFormat: FormatOpenAI,
		},
		{
			name:       "anthropic header case insensitive",
			path:       "/v1/chat/completions",
			header:     "Anthropic",
			wantFormat: FormatAnthropic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://localhost"+tt.path, nil)
			req.Header.Set("X-SB-Format", tt.header)
			got := DetectFormat(req)
			if got != tt.wantFormat {
				t.Errorf("DetectFormat() = %q, want %q", got, tt.wantFormat)
			}
		})
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	tests := []struct {
		path string
	}{
		{"/v1/models"},
		{"/v1/embeddings"},
		{"/v1/unknown"},
		{"/something/else"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost"+tt.path, nil)
			got := DetectFormat(req)
			if got != FormatUnknown {
				t.Errorf("DetectFormat(%q) = %q, want %q", tt.path, got, FormatUnknown)
			}
		})
	}
}
