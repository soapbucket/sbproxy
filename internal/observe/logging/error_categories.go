// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

// Error categories for diagnosing request failures.
const (
	// ErrorCategoryConfig is a sentinel error for or category config conditions.
	ErrorCategoryConfig = "config" // Config loading, parsing, validation
	// ErrorCategoryTemplate is a sentinel error for or category template conditions.
	ErrorCategoryTemplate = "template" // Template compilation or execution
	// ErrorCategoryUpstream is a sentinel error for or category upstream conditions.
	ErrorCategoryUpstream = "upstream" // Upstream/origin server errors
	// ErrorCategoryCache is a sentinel error for or category cache conditions.
	ErrorCategoryCache = "cache" // Cache read/write failures
	// ErrorCategoryAuth is a sentinel error for or category auth conditions.
	ErrorCategoryAuth = "auth" // Authentication/authorization failures
	// ErrorCategoryTransform is a sentinel error for or category transform conditions.
	ErrorCategoryTransform = "transform" // Response transformation errors
	// ErrorCategoryTransport is a sentinel error for or category transport conditions.
	ErrorCategoryTransport = "transport" // HTTP transport errors
	// ErrorCategoryInternal is a sentinel error for or category internal conditions.
	ErrorCategoryInternal = "internal" // Internal server errors (bugs)
)

// Error sources for distinguishing who can fix the problem.
const (
	// ErrorSourceConfig is a sentinel error for or source config conditions.
	ErrorSourceConfig = "config" // Problem with origin configuration — operator can fix
	// ErrorSourceServer is a sentinel error for or source server conditions.
	ErrorSourceServer = "server" // Infrastructure/runtime problem — infra team
	// ErrorSourceClient is a sentinel error for or source client conditions.
	ErrorSourceClient = "client" // Client-side issue — bad request, auth failure
)

// Field keys for error categorization.
const (
	// FieldErrorCategory is a constant for field error category.
	FieldErrorCategory = "error_category"
	// FieldErrorSource is a constant for field error source.
	FieldErrorSource = "error_source"
)
