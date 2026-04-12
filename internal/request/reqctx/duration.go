// Package models defines shared data types, constants, and request/response models used across packages.
package reqctx

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Duration is a custom type that can unmarshal from both string (e.g., "30s", "100ms", "1d") and number (nanoseconds)
// It marshals to human-readable format (e.g., "30s", "1m")
// Supports "d" suffix for days (e.g., "1d" = 24h, "7d" = 168h)
type Duration struct {
	time.Duration
}

// dayPattern matches day units in duration strings (e.g., "1d", "7d", "1d12h")
var dayPattern = regexp.MustCompile(`(\d+)d`)

// ExpandDays converts day units to hours (e.g., "1d" -> "24h", "7d12h" -> "168h12h")
func ExpandDays(s string) string {
	return dayPattern.ReplaceAllStringFunc(s, func(match string) string {
		// Extract the number before "d"
		days, err := strconv.Atoi(match[:len(match)-1])
		if err != nil {
			return match // Return unchanged if parsing fails
		}
		hours := days * 24
		return strconv.Itoa(hours) + "h"
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for Duration.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	var duration time.Duration
	switch value := v.(type) {
	case string:
		// Expand day units (e.g., "1d" -> "24h") before parsing
		expanded := ExpandDays(value)
		var err error
		duration, err = time.ParseDuration(expanded)
		if err != nil {
			return fmt.Errorf("invalid duration string %q: %w", value, err)
		}
	case float64:
		// JSON numbers are unmarshaled as float64
		duration = time.Duration(value)
	default:
		return fmt.Errorf("invalid duration type: %T", value)
	}

	// Note: Maximum duration validation is handled by validate tags on struct fields
	// This allows different max values for different use cases (e.g., timeouts vs TTLs)
	d.Duration = duration
	return nil
}

// MarshalJSON implements the json.Marshaler interface for Duration.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

