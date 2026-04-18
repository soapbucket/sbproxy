// Copyright 2026 Soap Bucket LLC. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package vault

import (
	"crypto/subtle"
)

// SecretValue wraps a string to prevent accidental logging or serialization.
// The fmt.Stringer implementation returns [REDACTED] instead of the actual
// value, protecting secrets from leaking into log output or debug traces.
type SecretValue struct {
	value string
}

// NewSecretValue creates a SecretValue wrapping the given string.
func NewSecretValue(s string) SecretValue {
	return SecretValue{value: s}
}

// Value returns the actual secret string. Use with care - the returned
// string has no redaction protection.
func (sv SecretValue) Value() string {
	return sv.value
}

// String implements fmt.Stringer, returning [REDACTED] to prevent
// accidental exposure of secret values in log output.
func (sv SecretValue) String() string {
	return "[REDACTED]"
}

// GoString implements fmt.GoStringer for %#v formatting.
func (sv SecretValue) GoString() string {
	return "SecretValue{[REDACTED]}"
}

// MarshalJSON prevents accidental JSON serialization of secrets.
// The secret value is replaced with the string "[REDACTED]".
func (sv SecretValue) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// MarshalText prevents accidental text serialization of secrets.
func (sv SecretValue) MarshalText() ([]byte, error) {
	return []byte("[REDACTED]"), nil
}

// Equal performs constant-time comparison of two secret values to prevent
// timing attacks. Returns true if both values are identical.
func (sv SecretValue) Equal(other SecretValue) bool {
	return subtle.ConstantTimeCompare([]byte(sv.value), []byte(other.value)) == 1
}

// IsEmpty returns true if the secret value is an empty string.
func (sv SecretValue) IsEmpty() bool {
	return sv.value == ""
}
