// Package hostfilter matches incoming requests to origin configurations based on hostname patterns.
package hostfilter

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
)

// FilterStats represents statistics about the host filter
type FilterStats struct {
	Size           uint      `json:"size"`
	EstimatedItems uint      `json:"estimated_items"`
	FPRate         float64   `json:"fp_rate"`
	LastRebuilt    time.Time `json:"last_rebuilt"`
}

// HostFilter provides bloom filter-based hostname pre-checking.
// It rejects hostnames that are definitely not in storage,
// preventing unnecessary database lookups for unknown hosts.
type HostFilter struct {
	mu             sync.RWMutex
	filter         *bloom.BloomFilter
	size           uint
	fpRate         float64
	estimatedItems uint
	maxHostnames   uint // Limit to prevent OOM from unbounded entries

	// Rebuild state
	storage     StorageKeyLister
	workspaceID string // When non-empty, filter only loads this workspace's hostnames
	interval    time.Duration
	jitter      float64
	cancel      context.CancelFunc

	// Debounced rebuild
	debounceMu    sync.Mutex
	debounceTimer *time.Timer

	lastRebuilt time.Time
}

// StorageKeyLister is the interface needed by the host filter for rebuilds
type StorageKeyLister interface {
	ListKeys(ctx context.Context) ([]string, error)
	ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error)
}

// New creates a new HostFilter with the given capacity and false positive rate
func New(estimatedItems uint, fpRate float64) *HostFilter {
	if estimatedItems == 0 {
		estimatedItems = 10000
	}
	if fpRate <= 0 {
		fpRate = 0.001
	}
	// Default maxHostnames: estimatedItems * 10 (reasonable headroom before rejecting)
	maxHostnames := estimatedItems * 10
	if maxHostnames == 0 {
		maxHostnames = 100000
	}
	return &HostFilter{
		filter:         bloom.NewWithEstimates(estimatedItems, fpRate),
		fpRate:         fpRate,
		estimatedItems: estimatedItems,
		maxHostnames:   maxHostnames,
	}
}

// Check returns true if the hostname might exist (proceed to storage),
// false if the hostname is definitely not in our origins.
// An empty hostname bypasses the filter (returns true).
func (hf *HostFilter) Check(hostname string) bool {
	if hostname == "" {
		return true
	}

	hostname = strings.ToLower(hostname)

	hf.mu.RLock()
	defer hf.mu.RUnlock()

	// 1. Check exact match (includes port if present)
	if hf.filter.TestString(hostname) {
		return true
	}

	// 2. If hostname contains a port, strip it and check again
	if host, _, err := net.SplitHostPort(hostname); err == nil && host != hostname && host != "" {
		if hf.filter.TestString(host) {
			return true
		}
		// Use stripped hostname for wildcard check
		hostname = host
	}

	// 3. Build single-level wildcard and check
	dotIdx := strings.IndexByte(hostname, '.')
	if dotIdx > 0 && dotIdx < len(hostname)-1 {
		wildcard := "*" + hostname[dotIdx:]
		if hf.filter.TestString(wildcard) {
			return true
		}
	}

	return false
}

// Reload atomically rebuilds the filter from a full hostname list
func (hf *HostFilter) Reload(hostnames []string) {
	n := uint(len(hostnames))
	if n > hf.maxHostnames {
		slog.Warn("hostname limit exceeded during filter reload",
			"max", hf.maxHostnames,
			"loaded", n)
	}
	if n == 0 {
		n = hf.estimatedItems
	}
	newFilter := bloom.NewWithEstimates(n, hf.fpRate)

	for _, h := range hostnames {
		newFilter.AddString(strings.ToLower(h))
	}

	hf.mu.Lock()
	hf.filter = newFilter
	hf.size = uint(len(hostnames))
	hf.lastRebuilt = time.Now()
	hf.mu.Unlock()

	slog.Info("host filter rebuilt", "hostname_count", len(hostnames))
}

// Add adds a single hostname to the filter (for incremental updates)
func (hf *HostFilter) Add(hostname string) {
	if hostname == "" {
		return
	}
	hostname = strings.ToLower(hostname)

	hf.mu.Lock()
	hf.filter.AddString(hostname)
	hf.size++
	hf.mu.Unlock()
}

// SetWorkspaceID restricts the host filter to a single workspace.
func (hf *HostFilter) SetWorkspaceID(id string) {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	hf.workspaceID = id
}

// WorkspaceID returns the configured workspace scope (empty = all workspaces).
func (hf *HostFilter) WorkspaceID() string {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	return hf.workspaceID
}

// SetMaxHostnames sets the maximum number of hostnames allowed
func (hf *HostFilter) SetMaxHostnames(max uint) {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	hf.maxHostnames = max
}

// Size returns the number of hostnames loaded into the filter
func (hf *HostFilter) Size() uint {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	return hf.size
}

// Stats returns filter statistics
func (hf *HostFilter) Stats() FilterStats {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	return FilterStats{
		Size:           hf.size,
		EstimatedItems: hf.estimatedItems,
		FPRate:         hf.fpRate,
		LastRebuilt:    hf.lastRebuilt,
	}
}

// Stop cancels the periodic rebuild goroutine and debounce timer
func (hf *HostFilter) Stop() {
	if hf.cancel != nil {
		hf.cancel()
	}
	hf.debounceMu.Lock()
	if hf.debounceTimer != nil {
		hf.debounceTimer.Stop()
	}
	hf.debounceMu.Unlock()
}
