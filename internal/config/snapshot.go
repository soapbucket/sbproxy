// snapshot.go defines CompiledConfig, an immutable snapshot of compiled origins for lock-free request routing.
package config

import (
	"net/http"
	"strings"
)

// CompiledConfig is an immutable snapshot of all compiled origins. Once created,
// it is never modified. The service layer holds it behind an atomic.Pointer so
// that config reloads can swap in a new snapshot without locks. In-flight
// requests continue using the old snapshot until they complete; the old snapshot
// is then cleaned up after a grace period.
type CompiledConfig struct {
	origins map[string]*CompiledOrigin
}

func NewCompiledConfig(origins map[string]*CompiledOrigin) *CompiledConfig {
	return &CompiledConfig{origins: origins}
}

// Lookup returns the compiled origin for the given hostname, or nil.
// Strips port from host if present. This is the hot path - no allocations.
func (cc *CompiledConfig) Lookup(host string) *CompiledOrigin {
	if i := strings.LastIndexByte(host, ':'); i != -1 {
		host = host[:i]
	}
	return cc.origins[host]
}

func (cc *CompiledConfig) Origins() map[string]*CompiledOrigin {
	return cc.origins
}

// CompiledOrigin is a fully provisioned handler chain for one origin. It wraps
// the compiled http.Handler and tracks metadata (hostname, workspace) for
// routing and multi-tenant isolation. Immutable after creation.
type CompiledOrigin struct {
	id          string
	hostname    string
	workspaceID string
	version     string
	handler     http.Handler
	cleanup     func()
}

func NewCompiledOrigin(id, hostname, workspaceID, version string, handler http.Handler, cleanup func()) *CompiledOrigin {
	return &CompiledOrigin{
		id: id, hostname: hostname, workspaceID: workspaceID,
		version: version, handler: handler, cleanup: cleanup,
	}
}

func (co *CompiledOrigin) ID() string          { return co.id }
func (co *CompiledOrigin) Hostname() string    { return co.hostname }
func (co *CompiledOrigin) WorkspaceID() string { return co.workspaceID }
func (co *CompiledOrigin) Version() string     { return co.version }

func (co *CompiledOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	co.handler.ServeHTTP(w, r)
}

func (co *CompiledOrigin) Cleanup() {
	if co.cleanup != nil {
		co.cleanup()
	}
}
