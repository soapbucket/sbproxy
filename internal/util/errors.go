// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package util

import "errors"

// Error definitions for common operations
var (
	// System initialization errors
	ErrStorageNotInitialized       = errors.New("storage manager not initialized")
	// ErrOriginManagerNotInitialized is a sentinel error for origin manager not initialized conditions.
	ErrOriginManagerNotInitialized = errors.New("origin manager not initialized")

	// Request validation errors
	ErrRequestNil         = errors.New("request is nil")
	// ErrRequestURLNil is a sentinel error for request url nil conditions.
	ErrRequestURLNil      = errors.New("request URL is nil")
	// ErrRequestMethodEmpty is a sentinel error for request method empty conditions.
	ErrRequestMethodEmpty = errors.New("request method is empty")

	// Request processing errors
	ErrRecursiveRequestDetected = errors.New("recursive request detected")
	// ErrEmptyFingerprint is a sentinel error for empty fingerprint conditions.
	ErrEmptyFingerprint         = errors.New("generated empty fingerprint")

	// Lua/CEL processing errors
	ErrEmptyScriptProvided     = errors.New("empty script provided")
	// ErrScriptCompilationFailed is a sentinel error for script compilation failed conditions.
	ErrScriptCompilationFailed = errors.New("script compilation failed")
	// ErrNoJSONModifications is a sentinel error for no json modifications conditions.
	ErrNoJSONModifications     = errors.New("no JSON modifications returned")
	// ErrExpectedTableResult is a sentinel error for expected table result conditions.
	ErrExpectedTableResult     = errors.New("expected table result")
	// ErrNilAST is a sentinel error for nil ast conditions.
	ErrNilAST                  = errors.New("compilation produced nil AST")
	// ErrExpectedRefVal is a sentinel error for expected ref val conditions.
	ErrExpectedRefVal          = errors.New("expected ref.Val")

	// JSON processing errors
	ErrJSONModifierCreationFailed = errors.New("failed to create JSON modifier")
	// ErrJSONParseFailed is a sentinel error for json parse failed conditions.
	ErrJSONParseFailed            = errors.New("failed to parse input JSON")
	// ErrJSONMarshalFailed is a sentinel error for json marshal failed conditions.
	ErrJSONMarshalFailed          = errors.New("failed to marshal modified JSON")
)
