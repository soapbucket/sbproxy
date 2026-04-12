package util

import (
	"testing"
)

// TestRemoveDuplicates covers various edge cases for RemoveDuplicates.
func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		trim     bool
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			trim:     false,
			expected: []string{},
		},
		{
			name:     "nil slice",
			input:    nil,
			trim:     false,
			expected: nil,
		},
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			trim:     false,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all duplicates",
			input:    []string{"a", "a", "a"},
			trim:     false,
			expected: []string{"a"},
		},
		{
			name:     "mixed duplicates",
			input:    []string{"a", "b", "a", "c", "b", "d"},
			trim:     false,
			expected: []string{"a", "b", "c", "d"},
		},
		{
			name:     "single element",
			input:    []string{"x"},
			trim:     false,
			expected: []string{"x"},
		},
		{
			name:     "trim whitespace duplicates",
			input:    []string{"a", " a", "a ", " a "},
			trim:     true,
			expected: []string{"a"},
		},
		{
			name:     "trim false preserves whitespace",
			input:    []string{"a", " a", "a "},
			trim:     false,
			expected: []string{"a", " a", "a "},
		},
		{
			name:     "empty strings",
			input:    []string{"", "", "a", ""},
			trim:     false,
			expected: []string{"", "a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RemoveDuplicates(tc.input, tc.trim)

			if len(got) != len(tc.expected) {
				t.Fatalf("expected len %d, got len %d: %v", len(tc.expected), len(got), got)
			}

			for i, v := range got {
				if v != tc.expected[i] {
					t.Errorf("index %d: expected %q, got %q", i, tc.expected[i], v)
				}
			}
		})
	}
}

// TestMergeMap covers various edge cases for MergeMap.
func TestMergeMap(t *testing.T) {
	tests := []struct {
		name     string
		src1     Map
		src2     Map
		expected Map
	}{
		{
			name:     "both empty",
			src1:     Map{},
			src2:     Map{},
			expected: Map{},
		},
		{
			name:     "first empty",
			src1:     Map{},
			src2:     Map{"a": "1"},
			expected: Map{"a": "1"},
		},
		{
			name:     "second empty",
			src1:     Map{"a": "1"},
			src2:     Map{},
			expected: Map{"a": "1"},
		},
		{
			name:     "no overlap",
			src1:     Map{"a": "1", "b": "2"},
			src2:     Map{"c": "3", "d": "4"},
			expected: Map{"a": "1", "b": "2", "c": "3", "d": "4"},
		},
		{
			name:     "overlapping keys (src2 wins)",
			src1:     Map{"a": "1", "b": "2"},
			src2:     Map{"b": "override", "c": "3"},
			expected: Map{"a": "1", "b": "override", "c": "3"},
		},
		{
			name:     "nil src1",
			src1:     nil,
			src2:     Map{"a": "1"},
			expected: Map{"a": "1"},
		},
		{
			name:     "nil src2",
			src1:     Map{"a": "1"},
			src2:     nil,
			expected: Map{"a": "1"},
		},
		{
			name:     "both nil",
			src1:     nil,
			src2:     nil,
			expected: Map{},
		},
		{
			name:     "single map",
			src1:     Map{"key": "value"},
			src2:     Map{},
			expected: Map{"key": "value"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MergeMap(tc.src1, tc.src2)

			if len(got) != len(tc.expected) {
				t.Fatalf("expected len %d, got len %d: %v", len(tc.expected), len(got), got)
			}

			for k, v := range tc.expected {
				if gotV, ok := got[k]; !ok || gotV != v {
					t.Errorf("key %q: expected %q, got %q (exists=%v)", k, v, gotV, ok)
				}
			}
		})
	}
}

// TestMergeMap_DoesNotMutateInputs verifies that MergeMap returns a new map
// without modifying the original inputs.
func TestMergeMap_DoesNotMutateInputs(t *testing.T) {
	src1 := Map{"a": "1"}
	src2 := Map{"b": "2"}

	result := MergeMap(src1, src2)

	// Mutate the result
	result["c"] = "3"

	// Originals should be unchanged
	if _, ok := src1["c"]; ok {
		t.Error("src1 was mutated")
	}
	if _, ok := src2["c"]; ok {
		t.Error("src2 was mutated")
	}
}

// TestConstants verifies that critical header constants are defined.
func TestConstants(t *testing.T) {
	// Spot-check a few important constants are non-empty
	constants := map[string]string{
		"HeaderOrigin":      HeaderOrigin,
		"HeaderRequestID":   HeaderRequestID,
		"HeaderContentType": HeaderContentType,
		"ContentTypeJSON":   ContentTypeJSON,
		"ContentTypeHTML":   ContentTypeHTML,
	}

	for name, val := range constants {
		if val == "" {
			t.Errorf("constant %s should not be empty", name)
		}
	}
}

// TestErrors verifies that error sentinel values are distinct and non-nil.
func TestErrors(t *testing.T) {
	errs := []struct {
		name string
		err  error
	}{
		{"ErrStorageNotInitialized", ErrStorageNotInitialized},
		{"ErrOriginManagerNotInitialized", ErrOriginManagerNotInitialized},
		{"ErrRequestNil", ErrRequestNil},
		{"ErrRequestURLNil", ErrRequestURLNil},
		{"ErrRequestMethodEmpty", ErrRequestMethodEmpty},
		{"ErrRecursiveRequestDetected", ErrRecursiveRequestDetected},
		{"ErrEmptyFingerprint", ErrEmptyFingerprint},
		{"ErrEmptyScriptProvided", ErrEmptyScriptProvided},
		{"ErrScriptCompilationFailed", ErrScriptCompilationFailed},
		{"ErrNoJSONModifications", ErrNoJSONModifications},
		{"ErrExpectedTableResult", ErrExpectedTableResult},
		{"ErrNilAST", ErrNilAST},
		{"ErrExpectedRefVal", ErrExpectedRefVal},
		{"ErrJSONModifierCreationFailed", ErrJSONModifierCreationFailed},
		{"ErrJSONParseFailed", ErrJSONParseFailed},
		{"ErrJSONMarshalFailed", ErrJSONMarshalFailed},
	}

	for _, tc := range errs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Errorf("error %s should not be nil", tc.name)
			}
			if tc.err.Error() == "" {
				t.Errorf("error %s should have a non-empty message", tc.name)
			}
		})
	}
}

// TestConstants_HTTPStatusCodes verifies non-standard HTTP status codes.
func TestConstants_HTTPStatusCodes(t *testing.T) {
	tests := []struct {
		name  string
		code  int
		lower int
		upper int
	}{
		{"HttpStatusUnknownError", HttpStatusUnknownError, 520, 530},
		{"HttpStatusWebServerDown", HttpStatusWebServerDown, 520, 530},
		{"HttpStatusConnectionTimeout", HttpStatusConnectionTimeout, 520, 530},
		{"HttpStatusOriginUnreachable", HttpStatusOriginUnreachable, 520, 530},
		{"HttpStatusTimeoutOccured", HttpStatusTimeoutOccured, 520, 530},
		{"HttpStatusSSLHandshakeFailed", HttpStatusSSLHandshakeFailed, 520, 530},
		{"HttpStatusInvalidSSLCertificate", HttpStatusInvalidSSLCertificate, 520, 530},
		{"HttpStatusDown", HttpStatusDown, 530, 531},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.code < tc.lower || tc.code > tc.upper {
				t.Errorf("%s = %d, expected between %d and %d", tc.name, tc.code, tc.lower, tc.upper)
			}
		})
	}
}

// TestConstants_CacheControl verifies cache control directives are non-empty.
func TestConstants_CacheControl(t *testing.T) {
	directives := []struct {
		name  string
		value string
	}{
		{"CacheControlNoCache", CacheControlNoCache},
		{"CacheControlNoStore", CacheControlNoStore},
		{"CacheControlMaxAge", CacheControlMaxAge},
		{"CacheControlPublic", CacheControlPublic},
		{"CacheControlPrivate", CacheControlPrivate},
		{"CacheControlMustRevalidate", CacheControlMustRevalidate},
	}

	for _, tc := range directives {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				t.Errorf("%s should not be empty", tc.name)
			}
		})
	}
}

// TestConstants_ContentTypes verifies content type constants.
func TestConstants_ContentTypes(t *testing.T) {
	types := []struct {
		name  string
		value string
	}{
		{"ContentTypeJSON", ContentTypeJSON},
		{"ContentTypeHTML", ContentTypeHTML},
		{"ContentTypeXML", ContentTypeXML},
		{"ContentTypeText", ContentTypeText},
		{"ContentTypeOctetStream", ContentTypeOctetStream},
	}

	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				t.Errorf("%s should not be empty", tc.name)
			}
		})
	}
}

// TestErrors_Uniqueness verifies that all error sentinels have unique messages.
func TestErrors_Uniqueness(t *testing.T) {
	errs := []error{
		ErrStorageNotInitialized,
		ErrOriginManagerNotInitialized,
		ErrRequestNil,
		ErrRequestURLNil,
		ErrRequestMethodEmpty,
		ErrRecursiveRequestDetected,
		ErrEmptyFingerprint,
		ErrEmptyScriptProvided,
		ErrScriptCompilationFailed,
		ErrNoJSONModifications,
		ErrExpectedTableResult,
		ErrNilAST,
		ErrExpectedRefVal,
		ErrJSONModifierCreationFailed,
		ErrJSONParseFailed,
		ErrJSONMarshalFailed,
	}

	seen := make(map[string]bool)
	for _, e := range errs {
		msg := e.Error()
		if seen[msg] {
			t.Errorf("duplicate error message: %q", msg)
		}
		seen[msg] = true
	}
}
