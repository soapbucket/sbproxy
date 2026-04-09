// Package fingerprint generates TLS and HTTP fingerprints (JA3, JA4) for client identification.
package fingerprint

import (
	"net"
)

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

	// Wrap the connection with ConnectionTiming to track first byte read
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
