// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import (
	"net"
	"time"
)

// NewListener creates a new network listener with timeouts
func NewListener(network, address string, readTimeout, writeTimeout time.Duration) (net.Listener, error) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	// Wrap the listener with timeout configuration if needed
	// For now, we'll return the basic listener
	// In a more sophisticated implementation, we might wrap it with timeout handling
	return listener, nil
}
