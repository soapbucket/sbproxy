// Package session provides session management with cookie-based tracking and storage backends.
package session

import "time"

const (
	// DefaultExpiresSeconds is the default value for expires seconds.
	DefaultExpiresSeconds = 3600
	// DefaultCookieName is the default value for cookie name.
	DefaultCookieName = "_sb.s"
	// DefaultL2CacheTimeout is the default value for l2 cache timeout.
	DefaultL2CacheTimeout = 5 * time.Minute
	// DefaultMaxAge is the default value for max age.
	DefaultMaxAge = 3600
)
