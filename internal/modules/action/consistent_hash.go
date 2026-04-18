// consistent_hash.go implements consistent hashing with virtual nodes for
// session affinity routing.
//
// The hash ring maps virtual node hashes to real backend nodes. When a
// request arrives, its affinity key (derived from a header, cookie, or
// client IP) is hashed and the ring finds the nearest clockwise node.
// Virtual nodes (replicas) ensure even key distribution across backends.
//
// Adding or removing a node only remaps keys proportional to the node's
// share of the ring, minimizing session disruption during scaling events.
package action

import (
	"fmt"
	"hash/crc32"
	"sort"
	"sync"
)

const defaultReplicas = 150

// ConsistentHashConfig configures consistent hashing for sticky routing.
type ConsistentHashConfig struct {
	Source   string `json:"source" yaml:"source"`             // "header", "cookie", "ip"
	Key     string `json:"key,omitempty" yaml:"key"`          // header/cookie name
	Replicas int   `json:"replicas,omitempty" yaml:"replicas"` // virtual nodes per real node
}

// HashRing implements consistent hashing with virtual nodes.
type HashRing struct {
	mu       sync.RWMutex
	nodes    map[uint32]string // hash -> node name
	sorted   []uint32          // sorted hash values
	replicas int
	members  map[string]struct{} // real node names
}

// NewHashRing creates a new consistent hash ring. If replicas is zero or
// negative, defaultReplicas (150) is used.
func NewHashRing(replicas int) *HashRing {
	if replicas <= 0 {
		replicas = defaultReplicas
	}
	return &HashRing{
		nodes:    make(map[uint32]string),
		replicas: replicas,
		members:  make(map[string]struct{}),
	}
}

// AddNode adds a real node and its virtual replicas to the ring.
// If the node already exists, this is a no-op.
func (hr *HashRing) AddNode(node string) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	if _, exists := hr.members[node]; exists {
		return
	}
	hr.members[node] = struct{}{}

	for i := 0; i < hr.replicas; i++ {
		h := hashKey(fmt.Sprintf("%s#%d", node, i))
		hr.nodes[h] = node
		hr.sorted = append(hr.sorted, h)
	}

	sort.Slice(hr.sorted, func(i, j int) bool {
		return hr.sorted[i] < hr.sorted[j]
	})
}

// RemoveNode removes a real node and all its virtual replicas from the ring.
func (hr *HashRing) RemoveNode(node string) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	if _, exists := hr.members[node]; !exists {
		return
	}
	delete(hr.members, node)

	for i := 0; i < hr.replicas; i++ {
		h := hashKey(fmt.Sprintf("%s#%d", node, i))
		delete(hr.nodes, h)
	}

	// Rebuild sorted slice
	hr.sorted = hr.sorted[:0]
	for h := range hr.nodes {
		hr.sorted = append(hr.sorted, h)
	}
	sort.Slice(hr.sorted, func(i, j int) bool {
		return hr.sorted[i] < hr.sorted[j]
	})
}

// GetNode returns the node responsible for the given key.
// Returns an empty string if the ring is empty.
func (hr *HashRing) GetNode(key string) string {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	if len(hr.sorted) == 0 {
		return ""
	}

	h := hashKey(key)
	idx := sort.Search(len(hr.sorted), func(i int) bool {
		return hr.sorted[i] >= h
	})

	// Wrap around to the first node if past the end
	if idx >= len(hr.sorted) {
		idx = 0
	}

	return hr.nodes[hr.sorted[idx]]
}

// Nodes returns the list of real node names currently in the ring.
func (hr *HashRing) Nodes() []string {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	result := make([]string, 0, len(hr.members))
	for node := range hr.members {
		result = append(result, node)
	}
	return result
}

// hashKey produces a CRC32 hash for a given string key.
func hashKey(key string) uint32 {
	return crc32.ChecksumIEEE([]byte(key))
}
