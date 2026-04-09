// Package buffer provides buffered log writers with failover for resilient log delivery.
package buffer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// HybridBuffer uses memory for fast writes and spills to disk when needed
// Provides resilience when external systems are unavailable
type HybridBuffer struct {
	memory         *MemoryBuffer
	file           *FileBuffer
	spillThreshold int64 // Bytes before spilling to disk
	spilledCount   atomic.Int64
	mu             sync.RWMutex
}

// NewHybridBuffer creates a buffer that uses memory first, then disk spillover
func NewHybridBuffer(
	memoryCapacity int,
	memoryMaxBytes int64,
	diskPath string,
	diskMaxSize int64,
	writer WriterFunc,
) (*HybridBuffer, error) {
	// Create memory buffer
	memBuffer := NewMemoryBuffer(memoryCapacity, memoryMaxBytes, writer)

	// Create file buffer
	fileBuffer, err := NewFileBuffer(diskPath, diskMaxSize, writer)
	if err != nil {
		return nil, fmt.Errorf("failed to create file buffer: %w", err)
	}

	return &HybridBuffer{
		memory:         memBuffer,
		file:           fileBuffer,
		spillThreshold: memoryMaxBytes / 2, // Spill when 50% of memory full
		spilledCount:   atomic.Int64{},
	}, nil
}

// Write adds an entry, preferring memory but falling back to disk
func (h *HybridBuffer) Write(entry *Entry) error {
	h.mu.RLock()
	memBytes := h.memory.Bytes()
	h.mu.RUnlock()

	// Try memory first if below spill threshold
	if memBytes < h.spillThreshold {
		err := h.memory.Write(entry)
		if err == nil {
			return nil
		}
		// Fall through to file buffer if memory fails
	}

	// Use file buffer for persistence
	h.spilledCount.Add(1)
	_ = events.Publish(events.SystemEvent{
		Type:     events.EventBufferSpilledToDisk,
		Severity: events.SeverityInfo,
		Source:   "hybrid_buffer",
		Data: map[string]interface{}{
			"buffer_type": "hybrid",
		},
	})
	return h.file.Write(entry)
}

// Flush sends all buffered entries (memory then file) to ClickHouse
func (h *HybridBuffer) Flush(ctx context.Context) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var totalWritten int
	var lastErr error

	// Flush memory first (fast, hot data)
	memCount, memErr := h.memory.Flush(ctx)
	totalWritten += memCount
	if memErr != nil {
		lastErr = memErr
	}

	// Then flush file (if any spillover occurred)
	fileCount, fileErr := h.file.Flush(ctx)
	totalWritten += fileCount
	if fileErr != nil {
		lastErr = fileErr
	}

	if lastErr != nil {
		return totalWritten, lastErr
	}

	return totalWritten, nil
}

// Size returns total entries in both buffers
func (h *HybridBuffer) Size() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.memory.Size() + h.file.Size()
}

// Bytes returns total bytes in both buffers
func (h *HybridBuffer) Bytes() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.memory.Bytes() + h.file.Bytes()
}

// IsFull returns true if either buffer is full
func (h *HybridBuffer) IsFull() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.memory.IsFull() || h.file.IsFull()
}

// Stats returns combined buffer statistics
func (h *HybridBuffer) Stats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	memStats := h.memory.Stats()
	fileStats := h.file.Stats()

	return Stats{
		Size:          memStats.Size + fileStats.Size,
		Bytes:         memStats.Bytes + fileStats.Bytes,
		Capacity:      memStats.Capacity,
		MaxBytes:      memStats.MaxBytes + fileStats.MaxBytes,
		Dropped:       memStats.Dropped + fileStats.Dropped,
		Flushed:       memStats.Flushed + fileStats.Flushed,
		FlushErrors:   memStats.FlushErrors + fileStats.FlushErrors,
		SpilledToDisk: h.spilledCount.Load(),
	}
}

// Close closes both buffers
func (h *HybridBuffer) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.memory != nil {
		_ = h.memory.Close()
	}
	if h.file != nil {
		_ = h.file.Close()
	}
	return nil
}
