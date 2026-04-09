// Package tlsutil provides shared TLS utility functions, certificate management,
// and connection timing types used across the proxy.
package tlsutil

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTLSKeyPairID is the default key pair ID for TLS certificates.
	DefaultTLSKeyPairID = "default"
)

// TLSKeyPair represents a TLS certificate and key pair.
type TLSKeyPair struct {
	Cert string
	Key  string
}

// CertManager manages TLS certificates.
type CertManager struct {
	keyPairs  map[string]TLSKeyPair
	configDir string
	logSender string
}

// NewCertManager creates a new certificate manager.
func NewCertManager(keyPairs []TLSKeyPair, configDir, logSender string) (*CertManager, error) {
	cm := &CertManager{
		keyPairs:  make(map[string]TLSKeyPair),
		configDir: configDir,
		logSender: logSender,
	}

	for i, kp := range keyPairs {
		key := DefaultTLSKeyPairID
		if i > 0 {
			key = fmt.Sprintf("keypair_%d", i)
		}
		cm.keyPairs[key] = kp
	}

	return cm, nil
}

// GetCertificateFunc returns a function that can be used as tls.Config.GetCertificate.
func (cm *CertManager) GetCertificateFunc(keyPairID string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kp, exists := cm.keyPairs[keyPairID]
		if !exists {
			kp, exists = cm.keyPairs[DefaultTLSKeyPairID]
			if !exists {
				return nil, fmt.Errorf("no certificate found for key pair ID: %s", keyPairID)
			}
		}

		cert, err := tls.LoadX509KeyPair(kp.Cert, kp.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}

		return &cert, nil
	}
}

// Reload reloads the certificate manager (placeholder implementation).
func (cm *CertManager) Reload() error {
	return nil
}

// GetTLSVersion returns the TLS version constant from an integer value.
// Default is TLS 1.3 for security. TLS 1.2 requires explicit opt-in.
func GetTLSVersion(val int) uint16 {
	switch val {
	case 12:
		slog.Warn("SECURITY WARNING: TLS 1.2 is enabled. Consider upgrading to TLS 1.3",
			"tls_version", "1.2",
			"risk", "vulnerable to downgrade attacks")
		return tls.VersionTLS12
	case 13:
		return tls.VersionTLS13
	default:
		slog.Info("using default TLS version 1.3")
		return tls.VersionTLS13
	}
}

// GetTLSCiphersFromNames returns the TLS ciphers from the specified names.
func GetTLSCiphersFromNames(cipherNames []string) []uint16 {
	var ciphers []uint16

	for _, name := range slices.CompactFunc(cipherNames, func(s1, s2 string) bool {
		return strings.TrimSpace(s1) == strings.TrimSpace(s2)
	}) {
		for _, c := range tls.CipherSuites() {
			if c.Name == strings.TrimSpace(name) {
				ciphers = append(ciphers, c.ID)
			}
		}
	}

	return ciphers
}

// ConnectionTiming represents a connection timing.
type ConnectionTiming struct {
	ConnectedAt time.Time
	FirstByteAt time.Time

	net.Conn
}

// NewConnectionTiming creates and initializes a new ConnectionTiming.
func NewConnectionTiming(conn net.Conn) *ConnectionTiming {
	return &ConnectionTiming{
		Conn:        conn,
		ConnectedAt: time.Now(),
		FirstByteAt: time.Time{},
	}
}

// Duration performs the duration operation on the ConnectionTiming.
func (c *ConnectionTiming) Duration() time.Duration {
	if c.FirstByteAt.IsZero() {
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

// QUICConnectionTiming tracks timing for QUIC/HTTP3 connections.
type QUICConnectionTiming struct {
	ConnectedAt time.Time
	FirstByteAt time.Time

	mu sync.RWMutex
}

// NewQUICConnectionTiming creates a new QUIC connection timing tracker.
func NewQUICConnectionTiming() *QUICConnectionTiming {
	return &QUICConnectionTiming{
		ConnectedAt: time.Now(),
		FirstByteAt: time.Time{},
	}
}

// MarkFirstByte records when the first request/data arrives on this QUIC connection.
func (q *QUICConnectionTiming) MarkFirstByte() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.FirstByteAt.IsZero() {
		q.FirstByteAt = time.Now()
	}
}

// Duration returns the time from connection to first byte/request.
func (q *QUICConnectionTiming) Duration() time.Duration {
	q.mu.RLock()
	firstByteAt := q.FirstByteAt
	connectedAt := q.ConnectedAt
	q.mu.RUnlock()

	if firstByteAt.IsZero() {
		return 0
	}
	return firstByteAt.Sub(connectedAt)
}

// GetConnectedAt returns the connection establishment time (thread-safe).
func (q *QUICConnectionTiming) GetConnectedAt() time.Time {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.ConnectedAt
}

// GetFirstByteAt returns the first byte time (thread-safe).
func (q *QUICConnectionTiming) GetFirstByteAt() time.Time {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.FirstByteAt
}

// TimingListener wraps a net.Listener and automatically wraps each accepted connection
// with ConnectionTiming to track when the first byte is read from the client.
type TimingListener struct {
	net.Listener
}

// NewTimingListener creates a new TimingListener that wraps the given listener.
func NewTimingListener(listener net.Listener) *TimingListener {
	return &TimingListener{Listener: listener}
}

// Accept wraps each accepted connection with ConnectionTiming.
func (tl *TimingListener) Accept() (net.Conn, error) {
	conn, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConnectionTiming(conn), nil
}

// Addr returns the listener's network address.
func (tl *TimingListener) Addr() net.Addr {
	return tl.Listener.Addr()
}

// Close closes the underlying listener.
func (tl *TimingListener) Close() error {
	return tl.Listener.Close()
}
