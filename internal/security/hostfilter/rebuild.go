// Package hostfilter matches incoming requests to origin configurations based on hostname patterns.
package hostfilter

import (
	"context"
	"log/slog"
	"math/rand"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const defaultDebounceWindow = 5 * time.Second

// StartPeriodicRebuild starts a background goroutine that periodically rebuilds the filter
func (hf *HostFilter) StartPeriodicRebuild(ctx context.Context, s StorageKeyLister, interval time.Duration, jitter float64) {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	if jitter <= 0 || jitter > 1.0 {
		jitter = 0.1
	}

	hf.storage = s
	hf.interval = interval
	hf.jitter = jitter

	rebuildCtx, cancel := context.WithCancel(ctx)
	hf.cancel = cancel

	go hf.rebuildLoop(rebuildCtx)
}

func (hf *HostFilter) rebuildLoop(ctx context.Context) {
	for {
		// Calculate next tick with jitter
		jitterRange := float64(hf.interval) * hf.jitter
		offset := (rand.Float64()*2 - 1) * jitterRange
		nextTick := hf.interval + time.Duration(offset)

		select {
		case <-ctx.Done():
			slog.Info("host filter rebuild loop stopped")
			return
		case <-time.After(nextTick):
			hf.doRebuild(ctx)
		}
	}
}

func (hf *HostFilter) doRebuild(ctx context.Context) {
	start := time.Now()
	var hostnames []string
	var err error
	if wsID := hf.WorkspaceID(); wsID != "" {
		hostnames, err = LoadHostnamesByWorkspace(ctx, hf.storage, wsID)
	} else {
		hostnames, err = LoadHostnames(ctx, hf.storage)
	}
	if err != nil {
		slog.Error("host filter rebuild failed", "error", err)
		return
	}
	hf.Reload(hostnames)
	duration := time.Since(start)
	metric.HostFilterRebuildDurationObserve(duration.Seconds())
	metric.HostFilterSizeSet(len(hostnames))
	slog.Info("host filter periodic rebuild completed",
		"duration", duration,
		"hostname_count", len(hostnames))
}

// ScheduleDebouncedRebuild schedules a rebuild after a debounce window.
// Multiple calls within the window batch into a single rebuild.
func (hf *HostFilter) ScheduleDebouncedRebuild(ctx context.Context) {
	hf.debounceMu.Lock()
	defer hf.debounceMu.Unlock()

	if hf.debounceTimer != nil {
		hf.debounceTimer.Stop()
	}

	hf.debounceTimer = time.AfterFunc(defaultDebounceWindow, func() {
		hf.doRebuild(ctx)
	})
}
