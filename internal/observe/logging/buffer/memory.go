// Package buffer provides buffered log writers with failover for resilient log delivery.
package buffer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// MemoryBuffer is a ring buffer that keeps logs in memory
// When full, new entries wrap around and overwrite old ones (bounded loss)
type MemoryBuffer struct {
	entries      []*Entry
	index        int   // Current write position
	size         int   // Current number of entries
	capacity     int   // Max capacity
	maxBytes     int64 // Max size in bytes
	currentBytes int64 // Current size
	mu           sync.RWMutex
	writer       WriterFunc   // Callback to actually write buffered data
	dropped      atomic.Int64 // Entries dropped due to overflow
	flushed      atomic.Int64 // Successfully flushed
	errors       atomic.Int64 // Flush errors
}

// NewMemoryBuffer creates a new in-memory ring buffer
func NewMemoryBuffer(capacity int, maxBytes int64, writer WriterFunc) *MemoryBuffer {
	return &MemoryBuffer{
		entries:  make([]*Entry, capacity),
		capacity: capacity,
		maxBytes: maxBytes,
		writer:   writer,
		dropped:  atomic.Int64{},
		flushed:  atomic.Int64{},
		errors:   atomic.Int64{},
	}
}

// Write adds an entry to the buffer (never blocks)
func (m *MemoryBuffer) Write(entry *Entry) error {
	if entry == nil || len(entry.Data) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	dataLen := int64(len(entry.Data))

	// Check if adding this entry would exceed max bytes
	if m.currentBytes+dataLen > m.maxBytes && m.size > 0 {
		m.dropped.Add(1)
		_ = events.Publish(events.SystemEvent{
			Type:      events.EventBufferOverflow,
			Severity:  events.SeverityWarning,
			Timestamp: time.Now(),
			Source:    "memory_buffer",
			Data: map[string]interface{}{
				"buffer_type": "memory",
				"reason":      "max_bytes",
			},
		})
		return fmt.Errorf("buffer full (bytes)")
	}

	// Ring buffer logic: write to current position and advance
	m.entries[m.index] = entry
	m.currentBytes += dataLen

	// If we're wrapping around, subtract the old entry's size
	if m.entries[(m.index+1)%m.capacity] != nil && m.size == m.capacity {
		oldEntry := m.entries[(m.index+1)%m.capacity]
		m.currentBytes -= int64(len(oldEntry.Data))
		m.dropped.Add(1)
		_ = events.Publish(events.SystemEvent{
			Type:      events.EventBufferOverflow,
			Severity:  events.SeverityWarning,
			Timestamp: time.Now(),
			Source:    "memory_buffer",
			Data: map[string]interface{}{
				"buffer_type": "memory",
				"reason":      "ring_overwrite",
			},
		})
	}

	// Update position and size
	m.index = (m.index + 1) % m.capacity
	if m.size < m.capacity {
		m.size++
	}

	return nil
}

// Flush sends all buffered entries to the writer
func (m *MemoryBuffer) Flush(ctx context.Context) (int, error) {
	m.mu.Lock()
	if m.size == 0 {
		m.mu.Unlock()
		return 0, nil
	}

	// Create slice of entries in order (accounting for ring buffer wrap-around)
	toFlush := make([]*Entry, m.size)
	start := m.index - m.size
	if start < 0 {
		start += m.capacity
	}
	for i := 0; i < m.size; i++ {
		idx := (start + i) % m.capacity
		toFlush[i] = m.entries[idx]
	}

	m.mu.Unlock()

	// Call writer with flushed entries
	if m.writer != nil {
		written, err := m.writer(ctx, toFlush)
		if err != nil {
			m.errors.Add(1)
			return written, err
		}
		m.flushed.Add(int64(written))
	}

	// Clear buffer on successful flush
	m.mu.Lock()
	m.entries = make([]*Entry, m.capacity)
	m.index = 0
	m.size = 0
	m.currentBytes = 0
	m.mu.Unlock()

	return len(toFlush), nil
}

// Size returns current number of entries
func (m *MemoryBuffer) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size
}

// Bytes returns current size in bytes
func (m *MemoryBuffer) Bytes() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentBytes
}

// IsFull returns true if buffer is at or near capacity
func (m *MemoryBuffer) IsFull() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Consider "full" at 80% to trigger early flush
	return m.size >= (m.capacity*80/100) || m.currentBytes >= (m.maxBytes*80/100)
}

// Stats returns current buffer statistics
func (m *MemoryBuffer) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Stats{
		Size:        m.size,
		Bytes:       m.currentBytes,
		Capacity:    m.capacity,
		MaxBytes:    m.maxBytes,
		Dropped:     m.dropped.Load(),
		Flushed:     m.flushed.Load(),
		FlushErrors: m.errors.Load(),
	}
}

// Close stops the buffer
func (m *MemoryBuffer) Close() error {
	// Attempt final flush on close
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = m.Flush(ctx)
	return nil
}
