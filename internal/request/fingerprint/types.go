// Package fingerprint generates TLS and HTTP fingerprints (JA3, JA4) for client identification.
package fingerprint

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Fingerprint represents a unique identifier for a user/client making requests
// This uses industry-standard techniques including:
// - IP address hashing
// - User-Agent fingerprinting
// - HTTP header analysis (similar to p0f, Panopticlick)
// - TLS fingerprinting (JA3 hash)
// - Cookie tracking
type Fingerprint struct {
	// Core identification
	Hash      string `json:"hash"`      // Unique fingerprint hash
	Composite string `json:"composite"` // Composite fingerprint string

	// Components (for analysis, not included in hash)
	IPHash        string `json:"ip_hash"`
	UserAgentHash string `json:"user_agent_hash"`
	HeaderPattern string `json:"header_pattern"`
	TLSHash       string `json:"tls_hash"`
	CookieCount   int    `json:"cookie_count"`

	ConnDuration time.Duration `json:"conn_duration"`

	// Metadata
	Version string `json:"version"`
}

// String returns a string representation of the fingerprint
func (f *Fingerprint) String() string {
	return fmt.Sprintf("%s:%s", f.Hash, f.ConnDuration.String())
}

// headerScore represents the scoring system for HTTP headers
// Based on industry-standard header fingerprinting techniques
type headerScore struct {
	name      string
	id        int
	weight    int64
	character rune
}

// ConnectionTiming represents a connection timing.
type ConnectionTiming struct {
	ConnectedAt time.Time
	FirstByteAt time.Time

	net.Conn
}

// Duration performs the duration operation on the ConnectionTiming.
func (c *ConnectionTiming) Duration() time.Duration {
	if c.FirstByteAt.IsZero() {
		// First byte hasn't been read yet, return zero duration
		return 0
	}
	return c.FirstByteAt.Sub(c.ConnectedAt)
}

// Read performs the read operation on the ConnectionTiming.
func (c *ConnectionTiming) Read(p []byte) (n int, err error) {
	if c.FirstByteAt.IsZero() {
		c.FirstByteAt = time.Now()
	}
	return c.Conn.Read(p)
}

// QUICConnectionTiming tracks timing for QUIC/HTTP3 connections
// Since QUIC connections work differently (using streams instead of direct Read),
// we track connection establishment and first request arrival time
type QUICConnectionTiming struct {
	ConnectedAt time.Time
	FirstByteAt time.Time

	mu sync.RWMutex
}

// NewQUICConnectionTiming creates a new QUIC connection timing tracker
func NewQUICConnectionTiming() *QUICConnectionTiming {
	return &QUICConnectionTiming{
		ConnectedAt: time.Now(),
		FirstByteAt: time.Time{}, // set when first request arrives
	}
}

// MarkFirstByte records when the first request/data arrives on this QUIC connection
// This should be called when the first HTTP request is received
func (q *QUICConnectionTiming) MarkFirstByte() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.FirstByteAt.IsZero() {
		q.FirstByteAt = time.Now()
	}
}

// Duration returns the time from connection to first byte/request
func (q *QUICConnectionTiming) Duration() time.Duration {
	q.mu.RLock()
	firstByteAt := q.FirstByteAt
	connectedAt := q.ConnectedAt
	q.mu.RUnlock()

	if firstByteAt.IsZero() {
		// First byte/request hasn't arrived yet, return zero duration
		return 0
	}
	return firstByteAt.Sub(connectedAt)
}

// GetConnectedAt returns the connection establishment time (thread-safe)
func (q *QUICConnectionTiming) GetConnectedAt() time.Time {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.ConnectedAt
}

// GetFirstByteAt returns the first byte time (thread-safe)
func (q *QUICConnectionTiming) GetFirstByteAt() time.Time {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.FirstByteAt
}
