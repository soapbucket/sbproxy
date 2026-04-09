package ai

import (
	"net/http"
	"testing"
)

func TestExtractMetadata(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		want    map[string]string
	}{
		{
			name:    "no meta headers",
			headers: map[string][]string{"Authorization": {"Bearer abc"}},
			want:    nil,
		},
		{
			name: "single meta header",
			headers: map[string][]string{
				"X-Sb-Meta-Team": {"backend"},
			},
			want: map[string]string{"team": "backend"},
		},
		{
			name: "multiple meta headers",
			headers: map[string][]string{
				"X-Sb-Meta-Team":    {"backend"},
				"X-Sb-Meta-Project": {"proxy"},
				"X-Sb-Meta-Env":     {"staging"},
			},
			want: map[string]string{"team": "backend", "project": "proxy", "env": "staging"},
		},
		{
			name: "case insensitive prefix",
			headers: map[string][]string{
				"x-sb-meta-lower": {"val1"},
				"X-SB-META-UPPER": {"val2"},
			},
			want: map[string]string{"lower": "val1", "upper": "val2"},
		},
		{
			name: "first value used when multiple values",
			headers: map[string][]string{
				"X-Sb-Meta-Tag": {"first", "second"},
			},
			want: map[string]string{"tag": "first"},
		},
		{
			name: "empty suffix ignored",
			headers: map[string][]string{
				"X-Sb-Meta-": {"val"},
			},
			want: nil,
		},
		{
			name:    "nil request",
			headers: nil,
			want:    nil,
		},
		{
			name: "mixed meta and non-meta headers",
			headers: map[string][]string{
				"X-Sb-Meta-Team":  {"backend"},
				"Authorization":   {"Bearer abc"},
				"X-Sb-Tag-Custom": {"not-meta"},
			},
			want: map[string]string{"team": "backend"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.headers == nil {
				got := ExtractMetadata(nil)
				if got != nil {
					t.Errorf("ExtractMetadata(nil) = %v, want nil", got)
				}
				return
			}

			r := &http.Request{Header: http.Header(tt.headers)}
			got := ExtractMetadata(r)

			if tt.want == nil {
				if got != nil {
					t.Errorf("ExtractMetadata() = %v, want nil", got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ExtractMetadata() returned %d entries, want %d", len(got), len(tt.want))
				return
			}

			for k, wantV := range tt.want {
				if gotV, ok := got[k]; !ok || gotV != wantV {
					t.Errorf("ExtractMetadata()[%q] = %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}

func TestExtractMetadataFromHeaders(t *testing.T) {
	h := http.Header{
		"X-Sb-Meta-Region": []string{"us-east-1"},
		"Content-Type":     []string{"application/json"},
	}

	got := ExtractMetadataFromHeaders(h)
	if got == nil || got["region"] != "us-east-1" {
		t.Errorf("ExtractMetadataFromHeaders() = %v, want region=us-east-1", got)
	}
	if len(got) != 1 {
		t.Errorf("ExtractMetadataFromHeaders() returned %d entries, want 1", len(got))
	}
}
