// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"errors"
	"io"
	"time"
)

// errNotAvailable is returned by all ClickHouse writer methods in the open-source build.
var errNotAvailable = errors.New("ClickHouse writer not available in this build")

// ClickHouseWriterConfig configures the HTTP writer.
type ClickHouseWriterConfig struct {
	Host          string        // ClickHouse host (e.g., "clickhouse:8123")
	Database      string        // Database name
	Table         string        // Table name
	MaxBatchSize  int           // Maximum records per batch (default: 1000)
	MaxBatchBytes int64         // Maximum bytes per batch (default: 1MB)
	FlushInterval time.Duration // Flush interval (default: 5s)
	Timeout       time.Duration // HTTP request timeout (default: 30s)
	AsyncInsert   bool          // Use ClickHouse async_insert (default: true)

	// Buffer configuration
	BufferType        string // "memory", "file", or "hybrid" (default: "hybrid")
	BufferCapacity    int    // Number of entries for memory buffer (default: 1000)
	BufferMaxBytes    int64  // Max bytes for memory buffer (default: 10MB)
	BufferDiskPath    string // Path for disk spillover
	BufferMaxDiskSize int64  // Max disk size (default: 1GB)
}

// ClickHouseHTTPWriter is a stub for the enterprise ClickHouse log writer.
// The full implementation is available in the enterprise build.
type ClickHouseHTTPWriter struct{}

// NewClickHouseHTTPWriter returns an error in the open-source build.
// The full implementation is provided by the enterprise build.
func NewClickHouseHTTPWriter(_ ClickHouseWriterConfig) (*ClickHouseHTTPWriter, error) {
	return nil, errNotAvailable
}

// Write implements io.Writer. Always returns the not-available error.
func (w *ClickHouseHTTPWriter) Write(p []byte) (int, error) {
	return 0, errNotAvailable
}

// Close is a no-op in the open-source build.
func (w *ClickHouseHTTPWriter) Close() error {
	return nil
}

// DroppedCount always returns 0 in the open-source build.
func (w *ClickHouseHTTPWriter) DroppedCount() int64 {
	return 0
}

// NewClickHouseMultiWriter wraps a writer in an io.MultiWriter.
// Preserved for API compatibility.
func NewClickHouseMultiWriter(clickhouseWriter io.Writer) io.Writer {
	return io.MultiWriter(clickhouseWriter)
}
