// manager.go deduplicates HTTP transports by configuration hash to prevent connection explosion.
package transport

import (
	"crypto/tls"
	"encoding/json"
	"hash/fnv"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// Manager deduplicates http.RoundTripper instances by hashing the TransportConfig.
// Identical configurations share a single pooled transport, preventing connection
// explosion when many origins share the same transport settings.
type Manager struct {
	mu         sync.RWMutex
	transports map[uint64]http.RoundTripper
}

// NewManager creates a Manager ready for use.
func NewManager() *Manager {
	return &Manager{transports: make(map[uint64]http.RoundTripper)}
}

// Get returns an http.RoundTripper for the given config, creating one if none
// exists yet for that configuration hash. Concurrent callers with the same
// config will share a single transport.
func (m *Manager) Get(cfg plugin.TransportConfig) http.RoundTripper {
	h := hashConfig(cfg)

	m.mu.RLock()
	if tr, ok := m.transports[h]; ok {
		m.mu.RUnlock()
		return tr
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after upgrading lock.
	if tr, ok := m.transports[h]; ok {
		return tr
	}
	tr := createTransport(cfg)
	m.transports[h] = tr
	return tr
}

// Len returns the number of distinct transports currently tracked.
func (m *Manager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.transports)
}

// hashConfig produces an FNV-1a hash of the JSON-marshaled config.
// JSON marshaling is deterministic for structs with fixed field order.
func hashConfig(cfg plugin.TransportConfig) uint64 {
	data, _ := json.Marshal(cfg)
	h := fnv.New64a()
	h.Write(data)
	return h.Sum64()
}

// createTransport builds an *http.Transport from plugin.TransportConfig with
// sensible defaults suitable for a reverse proxy workload.
func createTransport(cfg plugin.TransportConfig) http.RoundTripper {
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 100
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:           maxIdle,
		MaxIdleConnsPerHost:    maxIdle,
		IdleConnTimeout:        90 * time.Second,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  1 * time.Second,
		ForceAttemptHTTP2:      true,
		DisableCompression:     false,
		MaxResponseHeaderBytes: 0, // unlimited
	}
}
