package policy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// NetworkPolicy defines network-level access controls.
type NetworkPolicy struct {
	ID                string        `json:"id"`
	AllowedIPs        []string      `json:"allowed_ips,omitempty"`       // CIDR notation
	BlockedIPs        []string      `json:"blocked_ips,omitempty"`       // CIDR notation
	AuthFailureLimit  int           `json:"auth_failure_limit,omitempty"`
	AuthFailureWindow time.Duration `json:"auth_failure_window,omitempty"`
	RequireMTLS       bool          `json:"require_mtls,omitempty"`
}

// parsedNetworkPolicy caches parsed CIDRs for a policy.
type parsedNetworkPolicy struct {
	policy      *NetworkPolicy
	allowedNets []*net.IPNet
	blockedNets []*net.IPNet
}

// authFailureRecord tracks authentication failures for an IP.
type authFailureRecord struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// shardedAuthFailures provides concurrent access to auth failure records.
// Uses 16-way sharding to reduce lock contention.
const authFailureShards = 16

type authFailureShard struct {
	records map[string]*authFailureRecord
	mu      sync.RWMutex
}

// NetworkEnforcer evaluates network-level access policies.
type NetworkEnforcer struct {
	policies map[string]*parsedNetworkPolicy
	shards   [authFailureShards]authFailureShard
	mu       sync.RWMutex
}

// NewNetworkEnforcer creates a new network enforcer.
func NewNetworkEnforcer() *NetworkEnforcer {
	ne := &NetworkEnforcer{
		policies: make(map[string]*parsedNetworkPolicy),
	}
	for i := range ne.shards {
		ne.shards[i].records = make(map[string]*authFailureRecord)
	}
	return ne
}

// AddPolicy registers a network policy. CIDRs are parsed and cached on add.
func (ne *NetworkEnforcer) AddPolicy(policy *NetworkPolicy) error {
	parsed := &parsedNetworkPolicy{policy: policy}

	for _, cidr := range policy.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as single IP.
			ip := net.ParseIP(cidr)
			if ip == nil {
				return fmt.Errorf("invalid allowed IP/CIDR %q: %w", cidr, err)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		parsed.allowedNets = append(parsed.allowedNets, ipNet)
	}

	for _, cidr := range policy.BlockedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return fmt.Errorf("invalid blocked IP/CIDR %q: %w", cidr, err)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		parsed.blockedNets = append(parsed.blockedNets, ipNet)
	}

	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.policies[policy.ID] = parsed
	return nil
}

// CheckIP evaluates whether the given IP is allowed by the specified policy.
// Returns (allowed, reason). An empty reason means the IP is allowed.
func (ne *NetworkEnforcer) CheckIP(_ context.Context, policyID string, ip string) (bool, string) {
	ne.mu.RLock()
	parsed, ok := ne.policies[policyID]
	ne.mu.RUnlock()

	if !ok {
		return true, "" // no policy, allow by default
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Sprintf("invalid IP address: %s", ip)
	}

	// Check blocked list first (deny takes precedence).
	for _, blocked := range parsed.blockedNets {
		if blocked.Contains(parsedIP) {
			return false, fmt.Sprintf("IP %s is blocked by policy %s", ip, policyID)
		}
	}

	// If an allowlist exists, the IP must be in it.
	if len(parsed.allowedNets) > 0 {
		allowed := false
		for _, allow := range parsed.allowedNets {
			if allow.Contains(parsedIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, fmt.Sprintf("IP %s is not in allowlist for policy %s", ip, policyID)
		}
	}

	return true, ""
}

// getShard returns the shard for the given IP.
func (ne *NetworkEnforcer) getShard(ip string) *authFailureShard {
	h := uint32(0)
	for _, c := range ip {
		h = h*31 + uint32(c)
	}
	return &ne.shards[h%authFailureShards]
}

// RecordAuthFailure records an authentication failure for the given IP.
func (ne *NetworkEnforcer) RecordAuthFailure(ip string) {
	shard := ne.getShard(ip)

	shard.mu.RLock()
	rec, ok := shard.records[ip]
	shard.mu.RUnlock()

	if !ok {
		shard.mu.Lock()
		rec, ok = shard.records[ip]
		if !ok {
			rec = &authFailureRecord{}
			shard.records[ip] = rec
		}
		shard.mu.Unlock()
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.timestamps = append(rec.timestamps, time.Now())
}

// IsRateLimited checks whether the given IP has exceeded the auth failure limit
// in any active policy's failure window.
func (ne *NetworkEnforcer) IsRateLimited(ip string) bool {
	shard := ne.getShard(ip)

	shard.mu.RLock()
	rec, ok := shard.records[ip]
	shard.mu.RUnlock()

	if !ok {
		return false
	}

	ne.mu.RLock()
	defer ne.mu.RUnlock()

	now := time.Now()

	for _, parsed := range ne.policies {
		p := parsed.policy
		if p.AuthFailureLimit <= 0 || p.AuthFailureWindow <= 0 {
			continue
		}

		windowStart := now.Add(-p.AuthFailureWindow)

		rec.mu.Lock()
		// Prune old entries outside the window.
		pruned := rec.timestamps[:0]
		for _, t := range rec.timestamps {
			if t.After(windowStart) {
				pruned = append(pruned, t)
			}
		}
		rec.timestamps = pruned
		count := len(pruned)
		rec.mu.Unlock()

		if count >= p.AuthFailureLimit {
			return true
		}
	}

	return false
}
