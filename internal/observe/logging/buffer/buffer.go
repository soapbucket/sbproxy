// Package buffer provides log buffering for resilience when external systems are unavailable.
package buffer

import (
	"context"
	"time"
)

// Entry represents a single log entry in the buffer
type Entry struct {
	Data      []byte    // The log data (JSON)
	Timestamp time.Time // When the entry was added
	Attempt   int       // Retry attempt count
}

// Buffer defines the interface for log buffering
type Buffer interface {
	// Write adds an entry to the buffer. Never blocks, returns error if buffer full.
	Write(entry *Entry) error

	// Flush sends buffered entries to ClickHouse. Returns count of successfully flushed entries.
	Flush(ctx context.Context) (int, error)

	// Size returns current number of entries in buffer
	Size() int

	// Bytes returns current size in bytes
	Bytes() int64

	// IsFull returns true if buffer is at capacity and should flush
	IsFull() bool

	// Stats returns current buffer statistics
	Stats() Stats

	// Close gracefully shuts down the buffer
	Close() error
}

// Stats contains buffer statistics
type Stats struct {
	Size          int   // Current number of entries
	Bytes         int64 // Current size in bytes
	Capacity      int   // Max capacity
	MaxBytes      int64 // Max bytes
	Dropped       int64 // Total dropped due to overflow
	Flushed       int64 // Total successfully flushed
	FlushErrors   int64 // Total flush errors
	SpilledToDisk int64 // Times spilled to disk
}

// WriterFunc is a callback function that actually writes buffered data
// It receives the buffered entries and should return count written and any error
type WriterFunc func(ctx context.Context, entries []*Entry) (int, error)
