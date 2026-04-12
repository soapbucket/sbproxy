// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
//
// NOTE: New structured errors with codes and metadata should be added to
// internal/proxyerr/ instead of this file. The sentinel errors below are
// retained for backward compatibility with callers that use errors.Is().
package util

import "errors"

// Error definitions for common operations
var (
	// System initialization errors
	ErrStorageNotInitialized = errors.New("storage manager not initialized")
	// ErrOriginManagerNotInitialized is returned when the origin manager has not been initialized.
	ErrOriginManagerNotInitialized = errors.New("origin manager not initialized")

	// Request validation errors
	ErrRequestNil = errors.New("request is nil")
	// ErrRequestURLNil is returned when a request has a nil URL.
	ErrRequestURLNil = errors.New("request URL is nil")
	// ErrRequestMethodEmpty is returned when a request has an empty HTTP method.
	ErrRequestMethodEmpty = errors.New("request method is empty")

	// Request processing errors
	ErrRecursiveRequestDetected = errors.New("recursive request detected")
	// ErrEmptyFingerprint is returned when request fingerprinting produces an empty result.
	ErrEmptyFingerprint = errors.New("generated empty fingerprint")

	// Lua/CEL processing errors
	ErrEmptyScriptProvided = errors.New("empty script provided")
	// ErrScriptCompilationFailed is returned when a Lua or CEL script fails to compile.
	ErrScriptCompilationFailed = errors.New("script compilation failed")
	// ErrNoJSONModifications is returned when a script produces no JSON modifications.
	ErrNoJSONModifications = errors.New("no JSON modifications returned")
	// ErrExpectedTableResult is returned when a Lua script returns a non-table value.
	ErrExpectedTableResult = errors.New("expected table result")
	// ErrNilAST is returned when CEL compilation produces a nil AST.
	ErrNilAST = errors.New("compilation produced nil AST")
	// ErrExpectedRefVal is returned when a CEL evaluation does not produce a ref.Val.
	ErrExpectedRefVal = errors.New("expected ref.Val")

	// JSON processing errors
	ErrJSONModifierCreationFailed = errors.New("failed to create JSON modifier")
	// ErrJSONParseFailed is returned when JSON input cannot be parsed.
	ErrJSONParseFailed = errors.New("failed to parse input JSON")
	// ErrJSONMarshalFailed is returned when modified JSON cannot be marshaled back.
	ErrJSONMarshalFailed = errors.New("failed to marshal modified JSON")
)
