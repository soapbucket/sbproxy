// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	closers   []io.Closer
	closersMu sync.Mutex
)

// RegisterCloser registers an io.Closer to be called during logging shutdown.
func RegisterCloser(c io.Closer) {
	closersMu.Lock()
	closers = append(closers, c)
	closersMu.Unlock()
}

// Shutdown flushes and closes all log output backends.
// Must be called during graceful shutdown AFTER all request handling stops.
func Shutdown() {
	closersMu.Lock()
	defer closersMu.Unlock()
	for _, c := range closers {
		if err := c.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "logging shutdown error: %v\n", err)
		}
	}
	closers = nil
}
