// Package hostfilter matches incoming requests to origin configurations based on hostname patterns.
package hostfilter

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

var (
	hostFilterSubscriberOnce sync.Once
	hostFilterSubscriber     *hostFilterSub
	hostFilterSubscriberMu   sync.Mutex
)

type hostFilterSub struct {
	filter *HostFilter
	ctx    context.Context
	cancel context.CancelFunc
}

// hostFilterMessage matches the OriginCacheRefreshMessage format from configloader
type hostFilterMessage struct {
	ConfigID       string `json:"config_id"`
	ConfigHostname string `json:"config_hostname,omitempty"`
}

type hostFilterBatch struct {
	Updates []hostFilterMessage `json:"updates"`
}

// StartHostFilterSubscriber starts a subscriber that updates the bloom filter
// when origins are created, updated, or deleted.
func StartHostFilterSubscriber(ctx context.Context, m manager.Manager, filter *HostFilter, topic string) error {
	if filter == nil {
		return nil
	}

	hostFilterSubscriberOnce.Do(func() {
		subCtx, cancel := context.WithCancel(ctx)
		hostFilterSubscriber = &hostFilterSub{
			filter: filter,
			ctx:    subCtx,
			cancel: cancel,
		}

		msg := m.GetMessenger()
		if msg == nil {
			slog.Warn("messenger not available, host filter subscription disabled")
			return
		}

		slog.Info("subscribing to host filter messages", "topic", topic)
		err := msg.Subscribe(subCtx, topic, hostFilterSubscriber.handleMessage)
		if err != nil {
			slog.Error("failed to subscribe to host filter topic", "topic", topic, "error", err)
			cancel()
			return
		}
		slog.Info("host filter subscriber started", "topic", topic)
	})

	return nil
}

// StopHostFilterSubscriber stops the host filter subscriber
func StopHostFilterSubscriber() {
	hostFilterSubscriberMu.Lock()
	defer hostFilterSubscriberMu.Unlock()
	if hostFilterSubscriber != nil {
		hostFilterSubscriber.cancel()
		hostFilterSubscriber = nil
	}
	hostFilterSubscriberOnce = sync.Once{}
}

func (s *hostFilterSub) handleMessage(ctx context.Context, msg *messenger.Message) error {
	var updates []hostFilterMessage

	// Parse message body (same format as OriginCacheRefreshMessage)
	if len(msg.Body) > 0 {
		var batch hostFilterBatch
		if err := json.Unmarshal(msg.Body, &batch); err == nil && len(batch.Updates) > 0 {
			updates = batch.Updates
		} else {
			var single hostFilterMessage
			if err := json.Unmarshal(msg.Body, &single); err == nil && single.ConfigID != "" {
				updates = []hostFilterMessage{single}
			}
		}
	}

	// Fallback to params
	if len(updates) == 0 && msg.Params != nil {
		if id, ok := msg.Params["config_id"]; ok && id != "" {
			hostname := msg.Params["config_hostname"]
			updates = []hostFilterMessage{{ConfigID: id, ConfigHostname: hostname}}
		}
	}

	if len(updates) == 0 {
		return nil
	}

	needsRebuild := false
	for _, update := range updates {
		if update.ConfigHostname != "" {
			// Create or update: add hostname to filter
			s.filter.Add(update.ConfigHostname)
			slog.Debug("host filter updated", "hostname", update.ConfigHostname, "config_id", update.ConfigID)
		} else {
			// Delete case (no hostname): cannot remove from bloom filter, schedule rebuild
			needsRebuild = true
		}
	}

	if needsRebuild {
		slog.Info("host filter scheduling debounced rebuild due to delete")
		s.filter.ScheduleDebouncedRebuild(s.ctx)
	}

	return nil
}
