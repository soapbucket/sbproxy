package config

import (
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestValidateTags_DefaultValues(t *testing.T) {
	// Test that default values are applied
	config := &BaseConnection{}
	
	errors := validateStruct(config, "")
	if len(errors) > 0 {
		t.Logf("Validation errors (expected for zero values): %v", errors)
	}
	
	// After validation, defaults should be applied
	// Note: This is a simplified test - actual default application happens during UnmarshalJSON
}

func TestValidateTags_MaxValue(t *testing.T) {
	// Test max value validation
	config := &BaseConnection{
		Timeout: reqctx.Duration{Duration: 2 * time.Minute}, // Exceeds 1m limit
	}
	
	errors := validateStruct(config, "")
	if len(errors) == 0 {
		t.Error("expected validation error for timeout exceeding 1m")
	} else {
		found := false
		for _, err := range errors {
			if errorContains(err, "timeout") && errorContains(err, "exceeds maximum") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected timeout validation error, got: %v", errors)
		}
	}
}

func TestValidateTags_BufferSize(t *testing.T) {
	// Test buffer size validation
	config := &BaseConnection{
		WriteBufferSize: 20 * 1024 * 1024, // 20MB, exceeds 10MB limit
	}
	
	errors := validateStruct(config, "")
	if len(errors) == 0 {
		t.Error("expected validation error for write_buffer_size exceeding 10MB")
	} else {
		found := false
		for _, err := range errors {
			if errorContains(err, "write_buffer_size") && errorContains(err, "exceeds maximum") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected write_buffer_size validation error, got: %v", errors)
		}
	}
}

func TestValidateTags_StringSize(t *testing.T) {
	// Test string size validation
	config := &StreamingConfig{
		MaxBufferedBodySize: "20MB", // Exceeds 10MB limit
	}
	
	errors := validateStruct(config, "")
	if len(errors) == 0 {
		t.Error("expected validation error for max_buffered_body_size exceeding 10MB")
	} else {
		found := false
		for _, err := range errors {
			if errorContains(err, "max_buffered_body_size") && errorContains(err, "exceeds maximum") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected max_buffered_body_size validation error, got: %v", errors)
		}
	}
}

func TestValidateTags_DurationType(t *testing.T) {
	// Test Duration type validation
	config := &WebSocketConfig{
		PongTimeout: reqctx.Duration{Duration: 2 * time.Minute}, // Exceeds 1m limit
	}
	
	errors := validateStruct(config, "")
	if len(errors) == 0 {
		t.Error("expected validation error for pong_timeout exceeding 1m")
	} else {
		found := false
		for _, err := range errors {
			if errorContains(err, "pong_timeout") && errorContains(err, "exceeds maximum") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected pong_timeout validation error, got: %v", errors)
		}
	}
}

func TestParseValidateTag(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		expected *validateTag
	}{
		{
			name: "all values",
			tag:  "max_value=1m,default_value=30s,min_value=1s",
			expected: &validateTag{
				MaxValue:     "1m",
				DefaultValue: "30s",
				MinValue:     "1s",
			},
		},
		{
			name: "only max",
			tag:  "max_value=10MB",
			expected: &validateTag{
				MaxValue: "10MB",
			},
		},
		{
			name: "empty tag",
			tag:  "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseValidateTag(tt.tag)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.MaxValue != tt.expected.MaxValue {
				t.Errorf("MaxValue = %q, want %q", result.MaxValue, tt.expected.MaxValue)
			}
			if result.DefaultValue != tt.expected.DefaultValue {
				t.Errorf("DefaultValue = %q, want %q", result.DefaultValue, tt.expected.DefaultValue)
			}
			if result.MinValue != tt.expected.MinValue {
				t.Errorf("MinValue = %q, want %q", result.MinValue, tt.expected.MinValue)
			}
		})
	}
}

func errorContains(err string, substr string) bool {
	for i := 0; i <= len(err)-len(substr); i++ {
		if err[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestParseDurationWithDays(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		// Standard Go duration formats
		{
			name:     "seconds",
			input:    "30s",
			expected: 30 * time.Second,
		},
		{
			name:     "minutes",
			input:    "5m",
			expected: 5 * time.Minute,
		},
		{
			name:     "hours",
			input:    "2h",
			expected: 2 * time.Hour,
		},
		{
			name:     "complex duration",
			input:    "1h30m",
			expected: 1*time.Hour + 30*time.Minute,
		},

		// Day format (custom extension)
		{
			name:     "one day",
			input:    "1d",
			expected: 24 * time.Hour,
		},
		{
			name:     "seven days",
			input:    "7d",
			expected: 7 * 24 * time.Hour,
		},
		{
			name:     "thirty days",
			input:    "30d",
			expected: 30 * 24 * time.Hour,
		},
		{
			name:     "365 days",
			input:    "365d",
			expected: 365 * 24 * time.Hour,
		},

		// Compound durations with days
		{
			name:     "day with hours",
			input:    "1d12h",
			expected: 36 * time.Hour,
		},
		{
			name:     "day with minutes",
			input:    "2d30m",
			expected: 48*time.Hour + 30*time.Minute,
		},
		{
			name:     "day with hours and minutes",
			input:    "1d6h30m",
			expected: 30*time.Hour + 30*time.Minute,
		},

		// Edge cases
		{
			name:     "zero days",
			input:    "0d",
			expected: 0,
		},
		{
			name:     "zero",
			input:    "0s",
			expected: 0,
		},

		// Error cases
		{
			name:    "invalid format",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "invalid unit",
			input:   "5x",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDurationWithDays(tt.input)

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

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateTags_DayDurations(t *testing.T) {
	// Test that day-based duration validation works correctly
	// ABTestConfig has CookieTTL with max_value=365d
	tests := []struct {
		name      string
		duration  time.Duration
		wantError bool
	}{
		{
			name:      "30 days - valid",
			duration:  30 * 24 * time.Hour,
			wantError: false,
		},
		{
			name:      "365 days - valid at boundary",
			duration:  365 * 24 * time.Hour,
			wantError: false,
		},
		{
			name:      "366 days - exceeds max",
			duration:  366 * 24 * time.Hour,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ABTestConfig{
				CookieTTL: reqctx.Duration{Duration: tt.duration},
			}

			errors := validateStruct(config, "")

			if tt.wantError {
				if len(errors) == 0 {
					t.Error("expected validation error but got none")
				}
			} else {
				// Filter for cookie_ttl errors specifically
				var cookieTTLErrors []string
				for _, err := range errors {
					if errorContains(err, "cookie_ttl") {
						cookieTTLErrors = append(cookieTTLErrors, err)
					}
				}
				if len(cookieTTLErrors) > 0 {
					t.Errorf("unexpected cookie_ttl validation error: %v", cookieTTLErrors)
				}
			}
		})
	}
}

