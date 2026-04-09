// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/soapbucket/sbproxy/internal/proxyerr"
)

// Pre-compiled regexes for validation (avoid recompilation on every call)
var (
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// Validator provides common validation functions
type Validator struct {
	errors []error
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		errors: make([]error, 0),
	}
}

// AddError adds an error to the validator
func (v *Validator) AddError(err error) {
	if err != nil {
		v.errors = append(v.errors, err)
	}
}

// AddErrorf adds a formatted error to the validator
func (v *Validator) AddErrorf(format string, args ...interface{}) {
	v.errors = append(v.errors, fmt.Errorf(format, args...))
}

// HasErrors returns true if there are validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// Error returns all validation errors as a single error
func (v *Validator) Error() error {
	if !v.HasErrors() {
		return nil
	}

	messages := make([]string, len(v.errors))
	for i, err := range v.errors {
		messages[i] = err.Error()
	}

	return proxyerr.ConfigValidationError(strings.Join(messages, "; "))
}

// Errors returns all validation errors
func (v *Validator) Errors() []error {
	return v.errors
}

// Common validation functions

// ValidateRequired validates that a field is not empty
func ValidateRequired(fieldName, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}

// ValidateURLField validates that a named field string is a valid URL
func ValidateURLField(fieldName, value string) error {
	if value == "" {
		return nil
	}

	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s must be a valid URL: %w", fieldName, err)
	}

	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s must include scheme and host", fieldName)
	}

	return nil
}

// ValidateHostnameField validates that a named field string is a valid hostname
func ValidateHostnameField(fieldName, value string) error {
	if value == "" {
		return nil
	}

	if !hostnameRegex.MatchString(value) {
		return fmt.Errorf("%s must be a valid hostname", fieldName)
	}

	return nil
}

// ValidatePort validates that a value is a valid port number
func ValidatePort(fieldName string, value int) error {
	if value < 0 || value > 65535 {
		return fmt.Errorf("%s must be between 0 and 65535", fieldName)
	}
	return nil
}

// ValidateRange validates that a value is within a range
func ValidateRange(fieldName string, value, min, max int) error {
	if value < min || value > max {
		return fmt.Errorf("%s must be between %d and %d", fieldName, min, max)
	}
	return nil
}

// ValidateOneOf validates that a value is one of the allowed values
func ValidateOneOf(fieldName, value string, allowed []string) error {
	if value == "" {
		return nil
	}

	for _, a := range allowed {
		if value == a {
			return nil
		}
	}

	return fmt.Errorf("%s must be one of: %s", fieldName, strings.Join(allowed, ", "))
}

// ValidateRegex validates that a value matches a regex pattern
func ValidateRegex(fieldName, value, pattern string) error {
	if value == "" {
		return nil
	}

	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return fmt.Errorf("%s regex validation failed: %w", fieldName, err)
	}

	if !matched {
		return fmt.Errorf("%s does not match required pattern", fieldName)
	}

	return nil
}

// ValidateMinLength validates minimum string length
func ValidateMinLength(fieldName, value string, minLength int) error {
	if len(value) < minLength {
		return fmt.Errorf("%s must be at least %d characters", fieldName, minLength)
	}
	return nil
}

// ValidateMaxLength validates maximum string length
func ValidateMaxLength(fieldName, value string, maxLength int) error {
	if len(value) > maxLength {
		return fmt.Errorf("%s must be at most %d characters", fieldName, maxLength)
	}
	return nil
}

// ValidateEmail validates email format
func ValidateEmail(fieldName, value string) error {
	if value == "" {
		return nil
	}

	if !emailRegex.MatchString(value) {
		return fmt.Errorf("%s must be a valid email address", fieldName)
	}

	return nil
}

