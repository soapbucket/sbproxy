// Package buffer provides buffered log writers with failover for resilient log delivery.
package buffer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// FileBuffer stores logs on disk for persistent buffering
// Used when memory buffer is full and external systems are unavailable
type FileBuffer struct {
	path    string        // Directory path for spillover files
	maxSize int64         // Max disk size before blocking
	writer  WriterFunc    // Callback for actual writes
	file    *os.File      // Current file being written to
	encoder *json.Encoder // JSON encoder to file
	mu      sync.Mutex    // Lock for file operations
	size    int64         // Current total disk usage
	dropped atomic.Int64  // Dropped due to disk full
	flushed atomic.Int64  // Successfully flushed
	errors  atomic.Int64  // Flush errors
}

// NewFileBuffer creates a new file-based buffer
func NewFileBuffer(path string, maxSize int64, writer WriterFunc) (*FileBuffer, error) {
	// Create directory if needed
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create buffer directory: %w", err)
	}

	fb := &FileBuffer{
		path:    path,
		maxSize: maxSize,
		writer:  writer,
	}

	// Open initial file
	if err := fb.createNewFile(); err != nil {
		return nil, err
	}

	return fb, nil
}

// createNewFile opens a new spillover file
func (f *FileBuffer) createNewFile() error {
	filename := filepath.Join(f.path, fmt.Sprintf("spillover-%d.jsonl", os.Getpid()))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open spillover file: %w", err)
	}

	f.file = file
	f.encoder = json.NewEncoder(file)
	return nil
}

// Write appends an entry to the file buffer
func (f *FileBuffer) Write(entry *Entry) error {
	if entry == nil || len(entry.Data) == 0 {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Check disk usage
	newSize := f.size + int64(len(entry.Data))
	if newSize > f.maxSize {
		f.dropped.Add(1)
		_ = events.Publish(events.SystemEvent{
			Type:     events.EventBufferOverflow,
			Severity: events.SeverityWarning,
			Source:   "file_buffer",
			Data: map[string]interface{}{
				"buffer_type": "file",
				"reason":      "disk_full",
			},
		})
		return fmt.Errorf("disk spillover full (max %d bytes)", f.maxSize)
	}

	// Write as JSON line
	if err := f.encoder.Encode(entry); err != nil {
		f.errors.Add(1)
		return fmt.Errorf("failed to write entry: %w", err)
	}

	f.size += int64(len(entry.Data))
	return nil
}

// Flush reads all entries from disk and writes them
func (f *FileBuffer) Flush(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file == nil {
		return 0, nil
	}

	// Close current file
	currentFile := f.file
	filename := currentFile.Name()
	_ = currentFile.Close()

	// Read all entries from file
	entries, err := f.readEntriesFromFile(filename)
	if err != nil {
		f.errors.Add(1)
		// Recreate file for future writes
		_ = f.createNewFile()
		return 0, err
	}

	if len(entries) == 0 {
		// Clean up empty file
		_ = os.Remove(filename)
		_ = f.createNewFile()
		return 0, nil
	}

	// Call writer
	if f.writer != nil {
		written, err := f.writer(ctx, entries)
		if err != nil {
			f.errors.Add(1)
			// Recreate file for future writes
			_ = f.createNewFile()
			return written, err
		}
		f.flushed.Add(int64(written))
	}

	// Clean up file on success
	_ = os.Remove(filename)
	f.size = 0

	// Recreate file for future writes
	_ = f.createNewFile()

	return len(entries), nil
}

// readEntriesFromFile reads all JSON entries from a file
func (f *FileBuffer) readEntriesFromFile(filename string) ([]*Entry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var entries []*Entry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // Skip malformed entries
		}
		entries = append(entries, &entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return entries, nil
}

// Size returns number of entries (approximate, based on files on disk)
func (f *FileBuffer) Size() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	entries, _ := f.readEntriesFromFile(f.file.Name())
	return len(entries)
}

// Bytes returns current disk usage
func (f *FileBuffer) Bytes() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.size
}

// IsFull returns true if disk buffer is full
func (f *FileBuffer) IsFull() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.size >= f.maxSize
}

// Stats returns current buffer statistics
func (f *FileBuffer) Stats() Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	size := f.Size()
	return Stats{
		Size:          size,
		Bytes:         f.size,
		Capacity:      -1, // Unknown for file buffer
		MaxBytes:      f.maxSize,
		Dropped:       f.dropped.Load(),
		Flushed:       f.flushed.Load(),
		FlushErrors:   f.errors.Load(),
		SpilledToDisk: 1, // File buffer always counts as spilled
	}
}

// Close closes the file buffer
func (f *FileBuffer) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file != nil {
		_ = f.file.Close()
	}
	return nil
}
