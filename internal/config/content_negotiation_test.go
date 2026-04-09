package config

import (
	"testing"
)

func TestParseAcceptHeader(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		first    string
	}{
		{
			name:     "simple",
			input:    "application/json",
			expected: 1,
			first:    "application/json",
		},
		{
			name:     "multiple with quality",
			input:    "text/html, application/json;q=0.9, text/plain;q=0.8",
			expected: 3,
			first:    "text/html",
		},
		{
			name:     "wildcard lower priority",
			input:    "*/*;q=0.1, application/json",
			expected: 2,
			first:    "application/json",
		},
		{
			name:     "empty",
			input:    "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseAcceptHeader(tt.input)
			if len(result) != tt.expected {
				t.Errorf("expected %d entries, got %d", tt.expected, len(result))
				return
			}
			if tt.expected > 0 && result[0].Type != tt.first {
				t.Errorf("expected first type %s, got %s", tt.first, result[0].Type)
			}
		})
	}
}

func TestParseAcceptEncodingHeader(t *testing.T) {
	prefs := ParseAcceptEncodingHeader("gzip;q=0.8, br, identity;q=0.1")

	if len(prefs) != 3 {
		t.Fatalf("expected 3 preferences, got %d", len(prefs))
	}

	// br has highest quality (1.0 default)
	if prefs[0].Encoding != "br" {
		t.Errorf("expected br first, got %s", prefs[0].Encoding)
	}

	if prefs[1].Encoding != "gzip" {
		t.Errorf("expected gzip second, got %s", prefs[1].Encoding)
	}
}

func TestParseAcceptEncodingHeader_QualityZero(t *testing.T) {
	prefs := ParseAcceptEncodingHeader("gzip, br;q=0")

	if len(prefs) != 1 {
		t.Fatalf("expected 1 preference (br excluded with q=0), got %d", len(prefs))
	}

	if prefs[0].Encoding != "gzip" {
		t.Errorf("expected gzip, got %s", prefs[0].Encoding)
	}
}

func TestParseAcceptLanguageHeader(t *testing.T) {
	prefs := ParseAcceptLanguageHeader("en-US, en;q=0.9, fr;q=0.5")

	if len(prefs) != 3 {
		t.Fatalf("expected 3 preferences, got %d", len(prefs))
	}

	if prefs[0].Language != "en-US" {
		t.Errorf("expected en-US first, got %s", prefs[0].Language)
	}

	if prefs[2].Language != "fr" {
		t.Errorf("expected fr last, got %s", prefs[2].Language)
	}
}

func TestBestAcceptMatch(t *testing.T) {
	available := []string{"application/json", "text/html", "text/plain"}

	tests := []struct {
		name     string
		accept   string
		expected string
	}{
		{
			name:     "exact match",
			accept:   "application/json",
			expected: "application/json",
		},
		{
			name:     "quality ordering",
			accept:   "text/html;q=0.5, application/json",
			expected: "application/json",
		},
		{
			name:     "wildcard match",
			accept:   "*/*",
			expected: "application/json",
		},
		{
			name:     "type wildcard",
			accept:   "text/*",
			expected: "text/html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges := ParseAcceptHeader(tt.accept)
			result := BestAcceptMatch(available, ranges)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestMediaSpecificity(t *testing.T) {
	if mediaSpecificity("*/*") != 0 {
		t.Error("*/* should have specificity 0")
	}
	if mediaSpecificity("text/*") != 1 {
		t.Error("text/* should have specificity 1")
	}
	if mediaSpecificity("text/html") != 2 {
		t.Error("text/html should have specificity 2")
	}
}
