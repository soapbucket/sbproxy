// Package session provides session management with cookie-based tracking and storage backends.
package session

import "errors"

var (
	// ErrSessionServiceNotInitialized is a sentinel error for session service not initialized conditions.
	ErrSessionServiceNotInitialized = errors.New("session: session service not initialized")
)
