// Package loadbalancer implements the load_balancer action as a self-contained
// module registered into the pkg/plugin registry.
//
// It distributes incoming HTTP requests across a pool of backend targets using
// configurable algorithms (round-robin by default). Unhealthy targets are
// skipped when health state is available via the ServiceProvider.
//
// This package has zero imports from internal/config.
package loadbalancer

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/cespare/xxhash/v2"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("load_balancer", New)
}

// Algorithm constants match internal/config/constants.go.
const (
	AlgorithmWeightedRandom    = "weighted_random"
	AlgorithmRoundRobin        = "round_robin"
	AlgorithmWeightedRoundRobin = "weighted_round_robin"
	AlgorithmLeastConnections  = "least_connections"
	AlgorithmIPHash            = "ip_hash"
	AlgorithmURIHash           = "uri_hash"
	AlgorithmHeaderHash        = "header_hash"
	AlgorithmCookieHash        = "cookie_hash"
	AlgorithmRandom            = "random"
	AlgorithmFirst             = "first"
	AlgorithmConsistentHash    = "consistent_hash"
	AlgorithmPriorityFailover  = "priority_failover"
)

// Sentinel errors.
var (
	ErrNoTargets            = errors.New("loadbalancer: no targets configured")
	ErrInvalidTargetURL     = errors.New("loadbalancer: invalid target URL")
	ErrAllTargetsUnhealthy  = errors.New("loadbalancer: all targets are unhealthy")
	ErrTargetNotFound       = errors.New("loadbalancer: target index out of range")
)

// parsedTarget holds runtime state for one backend.
type parsedTarget struct {
	cfg *Target
	url *url.URL
}

// Handler is the load_balancer action handler.
type Handler struct {
	cfg       Config
	targets   []parsedTarget
	algorithm string
	hashKey   string

	// Lock-free round-robin counter.
	rrCounter int64

	// Consistent hash ring (built once during New, read-only after).
	hashRing *consistentHashRing

	// ServiceProvider for health state and transport (set during Provision).
	services plugin.ServiceProvider
}

// New is the ActionFactory for the load_balancer module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("loadbalancer: parse config: %w", err)
	}

	if len(cfg.Targets) == 0 && cfg.Discovery == nil {
		return nil, ErrNoTargets
	}

	// Validate algorithm.
	if cfg.Algorithm != "" {
		switch cfg.Algorithm {
		case AlgorithmWeightedRandom, AlgorithmRoundRobin, AlgorithmWeightedRoundRobin,
			AlgorithmLeastConnections, AlgorithmIPHash, AlgorithmURIHash,
			AlgorithmRandom, AlgorithmFirst, AlgorithmConsistentHash,
			AlgorithmPriorityFailover:
			// ok
		case AlgorithmHeaderHash, AlgorithmCookieHash:
			if cfg.HashKey == "" {
				return nil, fmt.Errorf("loadbalancer: algorithm %q requires a non-empty hash_key", cfg.Algorithm)
			}
		default:
			return nil, fmt.Errorf("loadbalancer: invalid algorithm %q", cfg.Algorithm)
		}
	}

	// Parse targets.
	targets := make([]parsedTarget, 0, len(cfg.Targets))
	for i, t := range cfg.Targets {
		if t.URL == "" {
			return nil, fmt.Errorf("loadbalancer: target[%d]: %w", i, ErrInvalidTargetURL)
		}
		u, err := url.Parse(t.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("loadbalancer: target[%d]: %w", i, ErrInvalidTargetURL)
		}
		targets = append(targets, parsedTarget{cfg: &cfg.Targets[i], url: u})
	}

	// Resolve algorithm.
	algo := cfg.Algorithm
	if algo == "" {
		switch {
		case cfg.LeastConnections:
			algo = AlgorithmLeastConnections
		case cfg.RoundRobin:
			algo = AlgorithmRoundRobin
		default:
			algo = AlgorithmRoundRobin // default for the new module
		}
	}

	h := &Handler{
		cfg:       cfg,
		targets:   targets,
		algorithm: algo,
		hashKey:   cfg.HashKey,
	}

	// Build consistent hash ring if using consistent_hash algorithm.
	if algo == AlgorithmConsistentHash {
		h.hashRing = newConsistentHashRing(targets, 150)
	}

	return h, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "load_balancer" }

// Provision receives origin-level context. Satisfies plugin.Provisioner.
func (h *Handler) Provision(ctx plugin.PluginContext) error {
	h.services = ctx.Services
	return nil
}

// Validate checks configuration validity. Satisfies plugin.Validator.
func (h *Handler) Validate() error {
	if len(h.targets) == 0 {
		return ErrNoTargets
	}
	return nil
}

// Cleanup stops background resources. Satisfies plugin.Cleanup.
func (h *Handler) Cleanup() error {
	return nil
}

// ServeHTTP selects a target via the configured algorithm and reverse-proxies
// the request. This is the primary request path.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	idx := h.selectTarget(r)
	if idx < 0 || idx >= len(h.targets) {
		slog.Error("loadbalancer: no healthy target available")
		http.Error(w, strconv.Itoa(http.StatusServiceUnavailable)+" "+http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	target := h.targets[idx]

	// Build the outbound URL.
	outURL := &url.URL{
		Scheme: target.url.Scheme,
		Host:   target.url.Host,
	}

	if h.cfg.StripBasePath {
		outURL.Path = r.URL.Path
	} else {
		if r.URL.Path == "/" && target.url.Path != "" && target.url.Path != "/" {
			outURL.Path = target.url.Path
		} else {
			outURL.Path = target.url.Path + r.URL.Path
		}
	}

	if h.cfg.PreserveQuery {
		outURL.RawQuery = r.URL.RawQuery
	} else {
		if r.URL.RawQuery != "" || target.url.RawQuery != "" {
			q := target.url.Query()
			for k, vs := range r.URL.Query() {
				for _, v := range vs {
					q.Add(k, v)
				}
			}
			outURL.RawQuery = q.Encode()
		}
	}

	// Use httputil.ReverseProxy for a single-shot proxy to the selected target.
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = outURL
			pr.Out.Host = target.url.Host
			pr.Out.Header.Set("Host", target.url.Host)
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			slog.Error("loadbalancer: upstream error", "url", outURL.String(), "error", err)
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			rw.Header().Set("X-Content-Type-Options", "nosniff")
			rw.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(rw, strconv.Itoa(http.StatusBadGateway)+" "+http.StatusText(http.StatusBadGateway))
		},
	}

	// Use ServiceProvider transport if available.
	if h.services != nil {
		rp.Transport = h.services.TransportFor(plugin.TransportConfig{
			InsecureSkipVerify: target.cfg.SkipTLSVerifyHost,
		})
	}

	rp.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// Target selection
// ---------------------------------------------------------------------------

// selectTarget picks a backend index using the configured algorithm.
// Returns -1 if no target is available.
func (h *Handler) selectTarget(r *http.Request) int {
	if len(h.targets) == 0 {
		return -1
	}
	if len(h.targets) == 1 {
		if !h.isTargetHealthy(0) {
			slog.Warn("loadbalancer: only target is unhealthy, using anyway")
		}
		return 0
	}

	switch h.algorithm {
	case AlgorithmRoundRobin:
		return h.selectRoundRobin()
	case AlgorithmIPHash:
		return h.selectIPHash(r)
	case AlgorithmURIHash:
		return h.selectURIHash(r)
	case AlgorithmHeaderHash:
		return h.selectHeaderHash(r)
	case AlgorithmCookieHash:
		return h.selectCookieHash(r)
	case AlgorithmFirst:
		return h.selectFirst()
	case AlgorithmConsistentHash:
		return h.selectConsistentHash(r)
	case AlgorithmPriorityFailover:
		return h.selectPriorityFailover()
	default:
		// round_robin as default
		return h.selectRoundRobin()
	}
}

// selectRoundRobin uses atomic counter for lock-free round-robin.
func (h *Handler) selectRoundRobin() int {
	n := len(h.targets)
	for attempts := 0; attempts < n; attempts++ {
		idx := int(atomic.AddInt64(&h.rrCounter, 1)-1) % n
		if h.isTargetHealthy(idx) {
			return idx
		}
	}
	return -1
}

// selectFirst returns the first healthy target (primary/failover pattern).
func (h *Handler) selectFirst() int {
	for i := range h.targets {
		if h.isTargetHealthy(i) {
			return i
		}
	}
	return -1
}

// fnvHash hashes a string with FNV-1a and returns index within n.
func fnvHash(s string, n int) int {
	hf := fnv.New32a()
	_, _ = hf.Write([]byte(s))
	return int(hf.Sum32()) % n
}

// selectHashHealthy probes forward from baseIndex to find a healthy target.
func (h *Handler) selectHashHealthy(base int) int {
	n := len(h.targets)
	for i := 0; i < n; i++ {
		idx := (base + i) % n
		if h.isTargetHealthy(idx) {
			return idx
		}
	}
	return -1
}

func (h *Handler) selectIPHash(r *http.Request) int {
	ip := r.RemoteAddr
	if host, _, found := strings.Cut(ip, ":"); found {
		ip = host
	}
	return h.selectHashHealthy(fnvHash(ip, len(h.targets)))
}

func (h *Handler) selectURIHash(r *http.Request) int {
	return h.selectHashHealthy(fnvHash(r.URL.Path, len(h.targets)))
}

func (h *Handler) selectHeaderHash(r *http.Request) int {
	v := r.Header.Get(h.hashKey)
	if v == "" {
		v = r.RemoteAddr
	}
	return h.selectHashHealthy(fnvHash(v, len(h.targets)))
}

func (h *Handler) selectCookieHash(r *http.Request) int {
	v := r.RemoteAddr
	if c, err := r.Cookie(h.hashKey); err == nil {
		v = c.Value
	}
	return h.selectHashHealthy(fnvHash(v, len(h.targets)))
}

// selectConsistentHash selects a target using consistent hashing on the request URL path.
// When a target is removed, only keys that mapped to that target are redistributed.
func (h *Handler) selectConsistentHash(r *http.Request) int {
	if h.hashRing == nil || len(h.targets) == 0 {
		return -1
	}
	key := r.URL.Path
	return h.hashRing.lookupHealthy(key, h.targets, h)
}

// selectPriorityFailover selects the first healthy target in array order.
// The target array order defines implicit priority: first target is highest priority.
// If all targets are unhealthy, returns -1.
func (h *Handler) selectPriorityFailover() int {
	for i := range h.targets {
		if h.isTargetHealthy(i) {
			return i
		}
	}
	return -1
}

// isTargetHealthy checks the ServiceProvider for health state.
// Returns true if no ServiceProvider is available (optimistic default).
func (h *Handler) isTargetHealthy(idx int) bool {
	if h.services == nil {
		return true
	}
	state := h.services.HealthStatus(h.targets[idx].url.String())
	return state.Healthy || state.ConsecutiveFailures == 0
}

// ---------------------------------------------------------------------------
// Consistent hash ring
// ---------------------------------------------------------------------------

// consistentHashRingEntry maps a hash value to a target index.
type consistentHashRingEntry struct {
	hash        uint64
	targetIndex int
}

// consistentHashRing implements a hash ring with virtual nodes for even distribution.
// The ring is built once during New and is read-only after construction, so no
// locking is required for lookups.
type consistentHashRing struct {
	entries []consistentHashRingEntry
}

// newConsistentHashRing builds a consistent hash ring with the specified number of
// virtual nodes per target. More virtual nodes produce more even distribution at
// the cost of slightly larger memory and O(log n) lookup time.
func newConsistentHashRing(targets []parsedTarget, virtualNodesPerTarget int) *consistentHashRing {
	ring := &consistentHashRing{
		entries: make([]consistentHashRingEntry, 0, len(targets)*virtualNodesPerTarget),
	}

	for i, target := range targets {
		baseKey := target.url.String()
		for v := 0; v < virtualNodesPerTarget; v++ {
			key := fmt.Sprintf("%s#%d", baseKey, v)
			h := xxhash.Sum64String(key)
			ring.entries = append(ring.entries, consistentHashRingEntry{
				hash:        h,
				targetIndex: i,
			})
		}
	}

	// Sort by hash value for binary search.
	sort.Slice(ring.entries, func(i, j int) bool {
		return ring.entries[i].hash < ring.entries[j].hash
	})

	return ring
}

// lookup finds the target index for a given key by walking clockwise around the ring.
func (r *consistentHashRing) lookup(key string) int {
	if len(r.entries) == 0 {
		return -1
	}

	h := xxhash.Sum64String(key)

	// Binary search for the first entry with hash >= h.
	idx := sort.Search(len(r.entries), func(i int) bool {
		return r.entries[i].hash >= h
	})

	// Wrap around to the first entry if past the end.
	if idx >= len(r.entries) {
		idx = 0
	}

	return r.entries[idx].targetIndex
}

// lookupHealthy finds a healthy target for the given key. It walks clockwise from
// the initial position, skipping unhealthy targets.
func (r *consistentHashRing) lookupHealthy(key string, targets []parsedTarget, h *Handler) int {
	if len(r.entries) == 0 {
		return -1
	}

	hash := xxhash.Sum64String(key)

	// Binary search for the first entry with hash >= hash.
	startIdx := sort.Search(len(r.entries), func(i int) bool {
		return r.entries[i].hash >= hash
	})
	if startIdx >= len(r.entries) {
		startIdx = 0
	}

	// Walk the ring looking for a healthy target. Track which target indexes
	// we have already checked so we stop after trying each distinct target once.
	seen := make(map[int]struct{}, len(targets))
	for i := 0; i < len(r.entries); i++ {
		entry := r.entries[(startIdx+i)%len(r.entries)]
		ti := entry.targetIndex

		if _, already := seen[ti]; already {
			continue
		}
		seen[ti] = struct{}{}

		if h.isTargetHealthy(ti) {
			return ti
		}

		// If we have checked every distinct target, stop early.
		if len(seen) == len(targets) {
			break
		}
	}

	return -1
}
