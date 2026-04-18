package httpkit

import (
	"testing"
)

func TestParseAccept_Simple(t *testing.T) {
	ranges := ParseAccept("application/json")
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if ranges[0].Type != "application/json" {
		t.Errorf("type = %q, want %q", ranges[0].Type, "application/json")
	}
	if ranges[0].Quality != 1.0 {
		t.Errorf("quality = %f, want 1.0", ranges[0].Quality)
	}
}

func TestParseAccept_Multiple(t *testing.T) {
	ranges := ParseAccept("text/html, application/json;q=0.9, text/plain;q=0.5")
	if len(ranges) != 3 {
		t.Fatalf("expected 3 ranges, got %d", len(ranges))
	}
	// Should be sorted by quality descending.
	if ranges[0].Type != "text/html" {
		t.Errorf("first = %q, want text/html", ranges[0].Type)
	}
	if ranges[1].Type != "application/json" {
		t.Errorf("second = %q, want application/json", ranges[1].Type)
	}
	if ranges[2].Type != "text/plain" {
		t.Errorf("third = %q, want text/plain", ranges[2].Type)
	}
}

func TestParseAccept_Empty(t *testing.T) {
	ranges := ParseAccept("")
	if len(ranges) != 0 {
		t.Fatalf("expected 0 ranges, got %d", len(ranges))
	}
}

func TestParseAccept_Wildcard(t *testing.T) {
	ranges := ParseAccept("*/*;q=0.1")
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if ranges[0].Type != "*/*" {
		t.Errorf("type = %q, want */*", ranges[0].Type)
	}
	if ranges[0].Quality != 0.1 {
		t.Errorf("quality = %f, want 0.1", ranges[0].Quality)
	}
}

func TestParseAccept_InvalidQuality(t *testing.T) {
	ranges := ParseAccept("text/html;q=abc")
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if ranges[0].Quality != 1.0 {
		t.Errorf("quality = %f, want 1.0 (default for invalid q)", ranges[0].Quality)
	}
}

func TestNegotiateContentType_ExactMatch(t *testing.T) {
	result := NegotiateContentType("application/json", []string{"text/html", "application/json"})
	if result != "application/json" {
		t.Errorf("got %q, want application/json", result)
	}
}

func TestNegotiateContentType_WildcardMatch(t *testing.T) {
	result := NegotiateContentType("*/*", []string{"text/html", "application/json"})
	if result != "text/html" {
		t.Errorf("got %q, want text/html (first available)", result)
	}
}

func TestNegotiateContentType_TypeWildcard(t *testing.T) {
	result := NegotiateContentType("text/*", []string{"application/json", "text/plain"})
	if result != "text/plain" {
		t.Errorf("got %q, want text/plain", result)
	}
}

func TestNegotiateContentType_NoMatch(t *testing.T) {
	result := NegotiateContentType("image/png", []string{"text/html", "application/json"})
	// Should fall back to first available.
	if result != "text/html" {
		t.Errorf("got %q, want text/html (fallback)", result)
	}
}

func TestNegotiateContentType_EmptyAvailable(t *testing.T) {
	result := NegotiateContentType("text/html", nil)
	if result != "" {
		t.Errorf("got %q, want empty", result)
	}
}

func TestNegotiateContentType_EmptyAccept(t *testing.T) {
	result := NegotiateContentType("", []string{"text/html"})
	if result != "text/html" {
		t.Errorf("got %q, want text/html", result)
	}
}

func TestNegotiateContentType_QualityOrdering(t *testing.T) {
	result := NegotiateContentType("text/html;q=0.5, application/json;q=0.9", []string{"text/html", "application/json"})
	if result != "application/json" {
		t.Errorf("got %q, want application/json (higher quality)", result)
	}
}

func TestMediaTypeMatches(t *testing.T) {
	tests := []struct {
		pattern  string
		concrete string
		want     bool
	}{
		{"*/*", "text/html", true},
		{"text/*", "text/html", true},
		{"text/*", "application/json", false},
		{"text/html", "text/html", true},
		{"text/html", "text/plain", false},
		{"*/*", "application/json", true},
		{"text", "text", true},
		{"text", "html", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.concrete, func(t *testing.T) {
			if got := mediaTypeMatches(tt.pattern, tt.concrete); got != tt.want {
				t.Errorf("mediaTypeMatches(%q, %q) = %v, want %v", tt.pattern, tt.concrete, got, tt.want)
			}
		})
	}
}
