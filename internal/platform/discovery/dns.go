package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// DNSConfig configures DNS SRV-based service discovery.
type DNSConfig struct {
	RefreshInterval time.Duration `json:"refresh_interval,omitempty"` // Default: 30s
	Resolver        string        `json:"resolver,omitempty"`         // Custom DNS resolver address
}

// DNSDiscoverer performs service discovery using DNS SRV records.
type DNSDiscoverer struct {
	config   DNSConfig
	resolver *net.Resolver

	mu       sync.RWMutex
	cache    map[string]cachedEndpoints
	watchers map[string][]func([]Endpoint)
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

type cachedEndpoints struct {
	endpoints []Endpoint
	expiresAt time.Time
}

// NewDNSDiscoverer creates a DNS SRV-based discoverer.
func NewDNSDiscoverer(config DNSConfig) *DNSDiscoverer {
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 30 * time.Second
	}

	var resolver *net.Resolver
	if config.Resolver != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, config.Resolver)
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	return &DNSDiscoverer{
		config:   config,
		resolver: resolver,
		cache:    make(map[string]cachedEndpoints),
		watchers: make(map[string][]func([]Endpoint)),
		stopCh:   make(chan struct{}),
	}
}

// Discover resolves DNS SRV records for the given service name and returns endpoints.
// The serviceName should be in the format used by SRV records (e.g., "_http._tcp.myservice").
func (d *DNSDiscoverer) Discover(ctx context.Context, serviceName string) ([]Endpoint, error) {
	d.mu.RLock()
	cached, ok := d.cache[serviceName]
	d.mu.RUnlock()

	if ok && time.Now().Before(cached.expiresAt) {
		return cached.endpoints, nil
	}

	endpoints, err := d.resolve(ctx, serviceName)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.cache[serviceName] = cachedEndpoints{
		endpoints: endpoints,
		expiresAt: time.Now().Add(d.config.RefreshInterval),
	}
	d.mu.Unlock()

	return endpoints, nil
}

// Watch starts a background goroutine that polls DNS at RefreshInterval and invokes
// the callback when the set of endpoints changes.
func (d *DNSDiscoverer) Watch(ctx context.Context, serviceName string, callback func([]Endpoint)) error {
	d.mu.Lock()
	d.watchers[serviceName] = append(d.watchers[serviceName], callback)
	d.mu.Unlock()

	d.wg.Add(1)
	go d.poll(ctx, serviceName)
	return nil
}

// Close stops all polling goroutines and releases resources.
func (d *DNSDiscoverer) Close() error {
	close(d.stopCh)
	d.wg.Wait()
	return nil
}

func (d *DNSDiscoverer) resolve(ctx context.Context, serviceName string) ([]Endpoint, error) {
	_, addrs, err := d.resolver.LookupSRV(ctx, "", "", serviceName)
	if err != nil {
		return nil, fmt.Errorf("discovery: DNS SRV lookup failed for %q: %w", serviceName, err)
	}

	endpoints := make([]Endpoint, 0, len(addrs))
	for _, srv := range addrs {
		target := srv.Target
		// Remove trailing dot from DNS name.
		if len(target) > 0 && target[len(target)-1] == '.' {
			target = target[:len(target)-1]
		}
		endpoints = append(endpoints, Endpoint{
			Address: target,
			Port:    int(srv.Port),
			Weight:  int(srv.Weight),
			Healthy: true,
		})
	}

	sortEndpoints(endpoints)
	return endpoints, nil
}

func (d *DNSDiscoverer) poll(ctx context.Context, serviceName string) {
	defer d.wg.Done()

	ticker := time.NewTicker(d.config.RefreshInterval)
	defer ticker.Stop()

	var last []Endpoint

	for {
		select {
		case <-d.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			resolved, err := d.resolve(ctx, serviceName)
			if err != nil {
				continue
			}

			if endpointsEqual(last, resolved) {
				continue
			}
			last = resolved

			d.mu.Lock()
			d.cache[serviceName] = cachedEndpoints{
				endpoints: resolved,
				expiresAt: time.Now().Add(d.config.RefreshInterval),
			}
			d.mu.Unlock()

			d.mu.RLock()
			cbs := make([]func([]Endpoint), len(d.watchers[serviceName]))
			copy(cbs, d.watchers[serviceName])
			d.mu.RUnlock()

			for _, cb := range cbs {
				cb(resolved)
			}
		}
	}
}

// sortEndpoints sorts by address then port for deterministic comparison.
func sortEndpoints(eps []Endpoint) {
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Address != eps[j].Address {
			return eps[i].Address < eps[j].Address
		}
		return eps[i].Port < eps[j].Port
	})
}

// endpointsEqual compares two sorted endpoint slices.
func endpointsEqual(a, b []Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Address != b[i].Address || a[i].Port != b[i].Port || a[i].Weight != b[i].Weight || a[i].Healthy != b[i].Healthy {
			return false
		}
	}
	return true
}
