// Package errors defines structured error types with HTTP status codes and machine-readable error codes.
package proxyerr

// Configuration error constructors

var (
	// ErrConfigNotFound is returned when a configuration is not found
	ErrConfigNotFound = New(ErrCodeConfigNotFound, "configuration not found")

	// ErrConfigInvalid is returned when a configuration is invalid
	ErrConfigInvalid = New(ErrCodeConfigInvalid, "configuration is invalid")
)

// ConfigLoadError creates a configuration loading error
func ConfigLoadError(cause error) *ProxyError {
	return Wrap(ErrCodeConfigLoad, "failed to load configuration", cause)
}

// ConfigParseError creates a configuration parsing error
func ConfigParseError(cause error) *ProxyError {
	return Wrap(ErrCodeConfigParse, "failed to parse configuration", cause)
}

// ConfigValidationError creates a configuration validation error
func ConfigValidationError(message string) *ProxyError {
	return New(ErrCodeConfigValidation, message)
}

// ConfigValidationErrorf creates a formatted configuration validation error
func ConfigValidationErrorf(format string, args ...interface{}) *ProxyError {
	return Wrapf(ErrCodeConfigValidation, nil, format, args...)
}

