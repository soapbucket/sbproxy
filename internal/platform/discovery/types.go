package discovery

import (
	"context"
	"fmt"
	"sync"
)

// Endpoint represents a discovered service endpoint.
type Endpoint struct {
	Address  string            `json:"address"`
	Port     int               `json:"port"`
	Weight   int               `json:"weight,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Healthy  bool              `json:"healthy"`
}

// Discoverer defines the interface for service discovery backends.
type Discoverer interface {
	// Discover returns the current list of endpoints for a service.
	Discover(ctx context.Context, serviceName string) ([]Endpoint, error)
	// Watch registers a callback invoked when endpoints change.
	Watch(ctx context.Context, serviceName string, callback func([]Endpoint)) error
	// Close stops discovery and releases resources.
	Close() error
}

// Registry manages multiple discovery backends.
type Registry struct {
	mu          sync.RWMutex
	discoverers map[string]Discoverer
}

func NewRegistry() *Registry {
	return &Registry{discoverers: make(map[string]Discoverer)}
}

func (r *Registry) Register(name string, d Discoverer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.discoverers[name] = d
}

func (r *Registry) Get(name string) (Discoverer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.discoverers[name]
	if !ok {
		return nil, fmt.Errorf("discovery: unknown backend %q", name)
	}
	return d, nil
}

func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.discoverers {
		d.Close()
	}
	return nil
}
