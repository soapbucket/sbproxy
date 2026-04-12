// consul.go implements service discovery via the Consul HTTP API.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ConsulConfig configures Consul-based service discovery.
type ConsulConfig struct {
	Address         string        `json:"address"`         // Consul HTTP API address (default: "http://localhost:8500")
	Token           string        `json:"token,omitempty"` // ACL token
	Datacenter      string        `json:"datacenter,omitempty"`
	RefreshInterval time.Duration `json:"refresh_interval,omitempty"` // Default: 10s
	PassingOnly     bool          `json:"passing_only"`               // Only return healthy services (default: true)
}

// ConsulDiscoverer performs service discovery via the Consul HTTP API.
type ConsulDiscoverer struct {
	config ConsulConfig
	client *http.Client

	mu       sync.RWMutex
	cache    map[string]cachedEndpoints
	watchers map[string][]func([]Endpoint)
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// consulHealthEntry represents a single entry from Consul's /v1/health/service API.
type consulHealthEntry struct {
	Node    consulNode    `json:"Node"`
	Service consulService `json:"Service"`
	Checks  []consulCheck `json:"Checks"`
}

type consulNode struct {
	Address string `json:"Address"`
}

type consulService struct {
	ID      string            `json:"ID"`
	Port    int               `json:"Port"`
	Tags    []string          `json:"Tags"`
	Meta    map[string]string `json:"Meta"`
	Weights consulWeights     `json:"Weights"`
}

type consulWeights struct {
	Passing int `json:"Passing"`
	Warning int `json:"Warning"`
}

type consulCheck struct {
	Status string `json:"Status"` // "passing", "warning", "critical"
}

// NewConsulDiscoverer creates a Consul-based discoverer.
func NewConsulDiscoverer(config ConsulConfig) *ConsulDiscoverer {
	if config.Address == "" {
		config.Address = "http://localhost:8500"
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 10 * time.Second
	}

	return &ConsulDiscoverer{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]cachedEndpoints),
		watchers: make(map[string][]func([]Endpoint)),
		stopCh:   make(chan struct{}),
	}
}

// Discover queries the Consul health API for the given service and returns endpoints.
func (c *ConsulDiscoverer) Discover(ctx context.Context, serviceName string) ([]Endpoint, error) {
	c.mu.RLock()
	cached, ok := c.cache[serviceName]
	c.mu.RUnlock()

	if ok && time.Now().Before(cached.expiresAt) {
		return cached.endpoints, nil
	}

	endpoints, _, err := c.fetch(ctx, serviceName, 0)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[serviceName] = cachedEndpoints{
		endpoints: endpoints,
		expiresAt: time.Now().Add(c.config.RefreshInterval),
	}
	c.mu.Unlock()

	return endpoints, nil
}

// Watch starts a background goroutine that polls Consul using blocking queries
// and invokes the callback when the set of endpoints changes.
func (c *ConsulDiscoverer) Watch(ctx context.Context, serviceName string, callback func([]Endpoint)) error {
	c.mu.Lock()
	c.watchers[serviceName] = append(c.watchers[serviceName], callback)
	c.mu.Unlock()

	c.wg.Add(1)
	go c.poll(ctx, serviceName)
	return nil
}

// Close stops all watchers and releases resources.
func (c *ConsulDiscoverer) Close() error {
	close(c.stopCh)
	c.wg.Wait()
	return nil
}

func (c *ConsulDiscoverer) fetch(ctx context.Context, serviceName string, waitIndex uint64) ([]Endpoint, uint64, error) {
	url := fmt.Sprintf("%s/v1/health/service/%s", c.config.Address, serviceName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("discovery: consul request build failed: %w", err)
	}

	q := req.URL.Query()
	if c.config.PassingOnly {
		q.Set("passing", "true")
	}
	if c.config.Datacenter != "" {
		q.Set("dc", c.config.Datacenter)
	}
	if waitIndex > 0 {
		q.Set("index", strconv.FormatUint(waitIndex, 10))
		q.Set("wait", "30s")
	}
	req.URL.RawQuery = q.Encode()

	if c.config.Token != "" {
		req.Header.Set("X-Consul-Token", c.config.Token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("discovery: consul request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("discovery: consul returned status %d: %s", resp.StatusCode, string(body))
	}

	var newIndex uint64
	if idx := resp.Header.Get("X-Consul-Index"); idx != "" {
		newIndex, _ = strconv.ParseUint(idx, 10, 64)
	}

	var entries []consulHealthEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, 0, fmt.Errorf("discovery: consul response decode failed: %w", err)
	}

	endpoints := make([]Endpoint, 0, len(entries))
	for _, entry := range entries {
		healthy := isHealthy(entry.Checks)
		if c.config.PassingOnly && !healthy {
			continue
		}

		weight := entry.Service.Weights.Passing
		if weight <= 0 {
			weight = 1
		}

		meta := make(map[string]string, len(entry.Service.Meta)+len(entry.Service.Tags))
		for k, v := range entry.Service.Meta {
			meta[k] = v
		}
		for i, tag := range entry.Service.Tags {
			meta[fmt.Sprintf("tag_%d", i)] = tag
		}

		endpoints = append(endpoints, Endpoint{
			Address:  entry.Node.Address,
			Port:     entry.Service.Port,
			Weight:   weight,
			Metadata: meta,
			Healthy:  healthy,
		})
	}

	sortEndpoints(endpoints)
	return endpoints, newIndex, nil
}

func (c *ConsulDiscoverer) poll(ctx context.Context, serviceName string) {
	defer c.wg.Done()

	var (
		waitIndex uint64
		last      []Endpoint
	)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		fetchCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		endpoints, newIndex, err := c.fetch(fetchCtx, serviceName, waitIndex)
		cancel()

		if err != nil {
			select {
			case <-c.stopCh:
				return
			case <-ctx.Done():
				return
			case <-time.After(c.config.RefreshInterval):
				continue
			}
		}

		waitIndex = newIndex

		if endpointsEqual(last, endpoints) {
			continue
		}
		last = endpoints

		c.mu.Lock()
		c.cache[serviceName] = cachedEndpoints{
			endpoints: endpoints,
			expiresAt: time.Now().Add(c.config.RefreshInterval),
		}
		c.mu.Unlock()

		c.mu.RLock()
		cbs := make([]func([]Endpoint), len(c.watchers[serviceName]))
		copy(cbs, c.watchers[serviceName])
		c.mu.RUnlock()

		for _, cb := range cbs {
			cb(endpoints)
		}
	}
}

// isHealthy returns true if all checks are passing.
func isHealthy(checks []consulCheck) bool {
	for _, c := range checks {
		if c.Status != "passing" {
			return false
		}
	}
	return true
}
