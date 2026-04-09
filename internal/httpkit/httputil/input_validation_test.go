package httputil

import (
	"strings"
	"testing"
)

func TestValidator(t *testing.T) {
	t.Run("empty validator", func(t *testing.T) {
		v := NewValidator()
		if v.HasErrors() {
			t.Error("new validator should have no errors")
		}

		if err := v.Error(); err != nil {
			t.Error("empty validator should return nil error")
		}
	})

	t.Run("add errors", func(t *testing.T) {
		v := NewValidator()
		v.AddErrorf("error 1")
		v.AddErrorf("error 2")

		if !v.HasErrors() {
			t.Error("validator should have errors")
		}

		if len(v.Errors()) != 2 {
			t.Errorf("expected 2 errors, got %d", len(v.Errors()))
		}
	})

	t.Run("combined error message", func(t *testing.T) {
		v := NewValidator()
		v.AddErrorf("error 1")
		v.AddErrorf("error 2")

		err := v.Error()
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// Should contain both error messages
		errStr := err.Error()
		if !strings.Contains(errStr, "error 1") || !strings.Contains(errStr, "error 2") {
			t.Errorf("combined error should contain both messages: %s", errStr)
		}
	})
}

func TestValidateRequired(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{"valid value", "test", false},
		{"empty string", "", true},
		{"whitespace only", "   ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequired("field", tt.value)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateRequired() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateURLField(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{"valid http url", "http://example.com", false},
		{"valid https url", "https://example.com/path", false},
		{"missing scheme", "example.com", true},
		{"invalid url", "ht!tp://example.com", true},
		{"empty string", "", false}, // Empty is allowed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLField("url", tt.value)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateURL() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name      string
		port      int
		wantError bool
	}{
		{"valid port", 8080, false},
		{"port 0", 0, false},
		{"max port", 65535, false},
		{"negative port", -1, true},
		{"port too high", 65536, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort("port", tt.port)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidatePort() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateRange(t *testing.T) {
	tests := []struct {
		name      string
		value     int
		min       int
		max       int
		wantError bool
	}{
		{"within range", 50, 0, 100, false},
		{"at min", 0, 0, 100, false},
		{"at max", 100, 0, 100, false},
		{"below min", -1, 0, 100, true},
		{"above max", 101, 0, 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRange("value", tt.value, tt.min, tt.max)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateRange() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateOneOf(t *testing.T) {
	allowed := []string{"foo", "bar", "baz"}

	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{"valid value", "foo", false},
		{"another valid", "bar", false},
		{"invalid value", "qux", true},
		{"empty string", "", false}, // Empty is allowed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOneOf("field", tt.value, allowed)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateOneOf() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateMinLength(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		minLength int
		wantError bool
	}{
		{"valid length", "hello", 3, false},
		{"exact length", "abc", 3, false},
		{"too short", "ab", 3, true},
		{"empty", "", 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMinLength("field", tt.value, tt.minLength)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateMinLength() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateMaxLength(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		maxLength int
		wantError bool
	}{
		{"within limit", "hello", 10, false},
		{"exact length", "abc", 3, false},
		{"too long", "abcdef", 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMaxLength("field", tt.value, tt.maxLength)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateMaxLength() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		wantError bool
	}{
		{"valid email", "user@example.com", false},
		{"valid with plus", "user+tag@example.com", false},
		{"invalid no @", "userexample.com", true},
		{"invalid no domain", "user@", true},
		{"invalid no tld", "user@example", true},
		{"empty", "", false}, // Empty is allowed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail("email", tt.email)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateEmail() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}


