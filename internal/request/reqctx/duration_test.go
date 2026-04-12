package reqctx

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDuration_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		// Standard Go duration formats
		{
			name:     "seconds",
			input:    `"30s"`,
			expected: 30 * time.Second,
		},
		{
			name:     "minutes",
			input:    `"5m"`,
			expected: 5 * time.Minute,
		},
		{
			name:     "hours",
			input:    `"2h"`,
			expected: 2 * time.Hour,
		},
		{
			name:     "milliseconds",
			input:    `"100ms"`,
			expected: 100 * time.Millisecond,
		},
		{
			name:     "complex duration",
			input:    `"1h30m"`,
			expected: 1*time.Hour + 30*time.Minute,
		},

		// Day format (custom extension)
		{
			name:     "one day",
			input:    `"1d"`,
			expected: 24 * time.Hour,
		},
		{
			name:     "seven days",
			input:    `"7d"`,
			expected: 7 * 24 * time.Hour,
		},
		{
			name:     "thirty days",
			input:    `"30d"`,
			expected: 30 * 24 * time.Hour,
		},
		{
			name:     "day with hours",
			input:    `"1d12h"`,
			expected: 36 * time.Hour,
		},
		{
			name:     "day with minutes",
			input:    `"2d30m"`,
			expected: 48*time.Hour + 30*time.Minute,
		},

		// Numeric (nanoseconds)
		{
			name:     "nanoseconds as number",
			input:    `1000000000`,
			expected: time.Second,
		},

		// Edge cases
		{
			name:     "zero duration",
			input:    `"0s"`,
			expected: 0,
		},
		{
			name:     "zero days",
			input:    `"0d"`,
			expected: 0,
		},

		// Error cases
		{
			name:    "invalid unit",
			input:   `"5x"`,
			wantErr: true,
		},
		{
			name:    "invalid format",
			input:   `"abc"`,
			wantErr: true,
		},
		{
			name:    "invalid type",
			input:   `true`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			err := json.Unmarshal([]byte(tt.input), &d)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if d.Duration != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, d.Duration)
			}
		})
	}
}

func TestDuration_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		duration Duration
		expected string
	}{
		{
			name:     "seconds",
			duration: Duration{30 * time.Second},
			expected: `"30s"`,
		},
		{
			name:     "minutes",
			duration: Duration{5 * time.Minute},
			expected: `"5m0s"`,
		},
		{
			name:     "hours",
			duration: Duration{2 * time.Hour},
			expected: `"2h0m0s"`,
		},
		{
			name:     "one day",
			duration: Duration{24 * time.Hour},
			expected: `"24h0m0s"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.duration)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if string(data) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, string(data))
			}
		})
	}
}

func TestDuration_RoundTrip(t *testing.T) {
	// Test that we can unmarshal day format and marshal back correctly
	original := `"1d"`
	var d Duration
	if err := json.Unmarshal([]byte(original), &d); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Should equal 24 hours
	if d.Duration != 24*time.Hour {
		t.Errorf("expected 24h, got %v", d.Duration)
	}

	// Marshal back - will be in Go's standard format
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Should be "24h0m0s"
	expected := `"24h0m0s"`
	if string(data) != expected {
		t.Errorf("expected %s, got %s", expected, string(data))
	}
}
