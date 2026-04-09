// Package metrics defines metric types and registration helpers for instrumentation.
package metric

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MetricsSnapshot represents a point-in-time snapshot of metrics
type MetricsSnapshot struct {
	Timestamp    time.Time            `json:"timestamp"`
	Period       time.Time            `json:"period"`
	Metrics      map[string]interface{} `json:"metrics"`
	CacheStats   map[string]interface{} `json:"cache_stats,omitempty"`
	BufferStats  map[string]interface{} `json:"buffer_stats,omitempty"`
	CircuitStats map[string]interface{} `json:"circuit_stats,omitempty"`
}

// SnapshotCollector gathers metrics and persists them to disk
type SnapshotCollector struct {
	snapshotDir   string
	interval      time.Duration
	retention     time.Duration // How long to keep snapshots
	stopCh        chan struct{}
	wg            sync.WaitGroup
	collectors    []MetricCollector
	mu            sync.RWMutex
}

// MetricCollector defines an interface for collecting metrics
type MetricCollector interface {
	Collect() map[string]interface{}
	Name() string
}

// NewSnapshotCollector creates a new metrics snapshot collector
func NewSnapshotCollector(snapshotDir string, interval time.Duration) (*SnapshotCollector, error) {
	// Create snapshot directory if it doesn't exist
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	if interval == 0 {
		interval = 1 * time.Minute // Default 1 minute interval
	}

	return &SnapshotCollector{
		snapshotDir: snapshotDir,
		interval:    interval,
		retention:   24 * time.Hour, // Keep snapshots for 24 hours by default
		stopCh:      make(chan struct{}),
		collectors:  make([]MetricCollector, 0),
	}, nil
}

// RegisterCollector registers a metric collector
func (sc *SnapshotCollector) RegisterCollector(collector MetricCollector) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.collectors = append(sc.collectors, collector)
	slog.Debug("metric collector registered", "name", collector.Name())
}

// Start begins the periodic snapshot collection
func (sc *SnapshotCollector) Start(ctx context.Context) {
	sc.wg.Add(1)
	go func() {
		defer sc.wg.Done()
		ticker := time.NewTicker(sc.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// Final snapshot before shutdown
				_ = sc.collectAndPersist()
				return
			case <-sc.stopCh:
				// Final snapshot before stop
				_ = sc.collectAndPersist()
				return
			case <-ticker.C:
				if err := sc.collectAndPersist(); err != nil {
					slog.Error("failed to collect metrics snapshot", "error", err)
				}
			}
		}
	}()

	// Background maintenance: clean old snapshots
	sc.wg.Add(1)
	go sc.cleanupOldSnapshots()
}

// collectAndPersist gathers all metrics and saves to disk
func (sc *SnapshotCollector) collectAndPersist() error {
	snapshot := MetricsSnapshot{
		Timestamp: time.Now(),
		Period:    time.Now().Truncate(time.Minute),
		Metrics:   make(map[string]interface{}),
	}

	// Collect metrics from all registered collectors
	sc.mu.RLock()
	collectors := sc.collectors
	sc.mu.RUnlock()

	for _, collector := range collectors {
		metrics := collector.Collect()
		for k, v := range metrics {
			snapshot.Metrics[fmt.Sprintf("%s_%s", collector.Name(), k)] = v
		}
	}

	// Persist to disk
	if err := sc.persistSnapshot(&snapshot); err != nil {
		return err
	}

	slog.Debug("metrics snapshot collected", "period", snapshot.Period.Format(time.RFC3339), "metrics_count", len(snapshot.Metrics))
	return nil
}

// persistSnapshot saves a snapshot to disk as JSONL
func (sc *SnapshotCollector) persistSnapshot(snapshot *MetricsSnapshot) error {
	// Create hourly snapshot file (one file per hour)
	hour := snapshot.Period.Format("2006-01-02-15")
	filename := filepath.Join(sc.snapshotDir, fmt.Sprintf("metrics_%s.jsonl", hour))

	// Open file in append mode
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open snapshot file: %w", err)
	}
	defer f.Close()

	// Marshal and write snapshot
	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write snapshot: %w", err)
	}

	return nil
}

// cleanupOldSnapshots removes snapshots older than retention period
func (sc *SnapshotCollector) cleanupOldSnapshots() {
	defer sc.wg.Done()
	ticker := time.NewTicker(time.Hour) // Clean up hourly
	defer ticker.Stop()

	for {
		select {
		case <-sc.stopCh:
			return
		case <-ticker.C:
			sc.cleanupSnapshots()
		}
	}
}

// cleanupSnapshots removes old snapshot files
func (sc *SnapshotCollector) cleanupSnapshots() {
	entries, err := os.ReadDir(sc.snapshotDir)
	if err != nil {
		slog.Error("failed to read snapshot directory", "error", err)
		return
	}

	cutoff := time.Now().Add(-sc.retention)
	removed := 0

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Remove if older than retention period
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(sc.snapshotDir, entry.Name())
			if err := os.Remove(path); err != nil {
				slog.Warn("failed to remove old snapshot", "path", path, "error", err)
			} else {
				removed++
			}
		}
	}

	if removed > 0 {
		slog.Debug("cleaned up old metric snapshots", "removed", removed)
	}
}

// LoadSnapshots loads all snapshots from disk (for recovery/analysis)
func (sc *SnapshotCollector) LoadSnapshots(maxAge time.Duration) ([]MetricsSnapshot, error) {
	entries, err := os.ReadDir(sc.snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	snapshots := make([]MetricsSnapshot, 0)

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}

		path := filepath.Join(sc.snapshotDir, entry.Name())
		info, _ := entry.Info()

		// Skip if older than maxAge
		if info.ModTime().Before(cutoff) {
			continue
		}

		// Load snapshots from file
		if fileSnapshots, err := sc.loadSnapshotFile(path); err == nil {
			snapshots = append(snapshots, fileSnapshots...)
		}
	}

	return snapshots, nil
}

// loadSnapshotFile loads all snapshots from a single JSONL file
func (sc *SnapshotCollector) loadSnapshotFile(path string) ([]MetricsSnapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open snapshot file: %w", err)
	}
	defer f.Close()

	snapshots := make([]MetricsSnapshot, 0)
	decoder := json.NewDecoder(f)

	for {
		var snapshot MetricsSnapshot
		if err := decoder.Decode(&snapshot); err != nil {
			if err == io.EOF {
				break
			}
			slog.Warn("failed to decode snapshot", "path", path, "error", err)
			continue
		}
		snapshots = append(snapshots, snapshot)
	}

	return snapshots, nil
}

// GetLatestSnapshot returns the most recent snapshot
func (sc *SnapshotCollector) GetLatestSnapshot() (*MetricsSnapshot, error) {
	snapshots, err := sc.LoadSnapshots(1 * time.Hour) // Load recent snapshots
	if err != nil {
		return nil, err
	}

	if len(snapshots) == 0 {
		return nil, fmt.Errorf("no snapshots available")
	}

	// Return the last one (most recent)
	return &snapshots[len(snapshots)-1], nil
}

// Stop gracefully stops the snapshot collector
func (sc *SnapshotCollector) Stop() error {
	close(sc.stopCh)
	sc.wg.Wait()
	return nil
}

// SnapshotStats represents snapshot statistics
type SnapshotStats struct {
	TotalSnapshots int
	OldestSnapshot time.Time
	NewestSnapshot time.Time
	TotalBytes     int64
	FileCount      int
}

// GetStats returns statistics about snapshots
func (sc *SnapshotCollector) GetStats() (*SnapshotStats, error) {
	entries, err := os.ReadDir(sc.snapshotDir)
	if err != nil {
		return nil, err
	}

	stats := &SnapshotStats{}
	var oldestTime, newestTime time.Time

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}

		info, _ := entry.Info()
		stats.TotalBytes += info.Size()
		stats.FileCount++

		modTime := info.ModTime()
		if oldestTime.IsZero() || modTime.Before(oldestTime) {
			oldestTime = modTime
		}
		if newestTime.IsZero() || modTime.After(newestTime) {
			newestTime = modTime
		}
	}

	stats.OldestSnapshot = oldestTime
	stats.NewestSnapshot = newestTime

	// Count total snapshot records by parsing files
	if snapshots, err := sc.LoadSnapshots(sc.retention); err == nil {
		stats.TotalSnapshots = len(snapshots)
	}

	return stats, nil
}
