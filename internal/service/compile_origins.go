// compile_origins.go compiles raw origin configs into the immutable CompiledConfig snapshot.
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// managerServiceProvider bridges the runtime Manager to the plugin.ServiceProvider
// interface required by CompileOrigin. Created once at startup and reused across
// config reloads so that upstream health state persists (a target marked unhealthy
// during one config generation stays unhealthy in the next).
type managerServiceProvider struct {
	m      manager.Manager
	ccm    *CompiledConfigManager
	logger *slog.Logger

	// healthMu guards healthMap. A sync.Map would also work but we expect
	// low contention (writes happen during health probes, reads during
	// origin compilation).
	healthMu sync.RWMutex
	health   map[string]plugin.HealthState
}

var _ plugin.ServiceProvider = (*managerServiceProvider)(nil)

func newManagerServiceProvider(m manager.Manager, ccm *CompiledConfigManager) *managerServiceProvider {
	return &managerServiceProvider{
		m:      m,
		ccm:    ccm,
		logger: slog.Default(),
		health: make(map[string]plugin.HealthState),
	}
}

func (sp *managerServiceProvider) KVStore() plugin.KVStore             { return nil }
func (sp *managerServiceProvider) Cache() plugin.CacheStore            { return nil }
func (sp *managerServiceProvider) ResponseCache() plugin.ResponseCache { return nil }
func (sp *managerServiceProvider) Sessions() plugin.SessionProvider {
	return &managerSessionProvider{m: sp.m}
}

// managerSessionProvider adapts the Manager's crypto and session cache
// to the plugin.SessionProvider interface used by the compiler.
type managerSessionProvider struct {
	m manager.Manager
}

func (msp *managerSessionProvider) Encrypt(data string) (string, error) {
	return msp.m.EncryptString(data)
}

func (msp *managerSessionProvider) Decrypt(data string) (string, error) {
	return msp.m.DecryptString(data)
}

func (msp *managerSessionProvider) SessionStore() plugin.KVStore {
	sc := msp.m.GetSessionCache()
	if sc == nil {
		return nil
	}
	return &sessionCacheKVStore{cache: sc}
}

// sessionCacheKVStore adapts manager.SessionCache (io.Reader-based) to
// plugin.KVStore ([]byte-based).
type sessionCacheKVStore struct {
	cache manager.SessionCache
}

func (s *sessionCacheKVStore) Get(ctx context.Context, key string) ([]byte, error) {
	reader, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

func (s *sessionCacheKVStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.cache.Put(ctx, key, bytes.NewReader(value), ttl)
}

func (s *sessionCacheKVStore) Delete(ctx context.Context, key string) error {
	return s.cache.Delete(ctx, key)
}

func (s *sessionCacheKVStore) Increment(_ context.Context, _ string, _ int64) (int64, error) {
	return 0, fmt.Errorf("increment not supported on session cache")
}
func (sp *managerServiceProvider) Logger() *slog.Logger     { return sp.logger }
func (sp *managerServiceProvider) Metrics() plugin.Observer { return plugin.NoopObserver() }

func (sp *managerServiceProvider) Events() plugin.EventEmitter {
	return &noopEventEmitter{}
}

func (sp *managerServiceProvider) TransportFor(_ plugin.TransportConfig) http.RoundTripper {
	return http.DefaultTransport
}

// ResolveOriginHandler resolves a hostname to its compiled handler, enabling
// forward rules and load-balancer origins to reference other compiled origins.
func (sp *managerServiceProvider) ResolveOriginHandler(hostname string) (http.Handler, error) {
	if sp.ccm == nil {
		return nil, fmt.Errorf("compiled config manager not available")
	}
	co := sp.ccm.LookupOrigin(hostname)
	if co == nil {
		return nil, fmt.Errorf("origin %q not found in compiled config", hostname)
	}
	return co, nil
}

func (sp *managerServiceProvider) ResolveEmbeddedOriginHandler(raw json.RawMessage) (http.Handler, error) {
	// Compile the embedded origin inline.
	var ro config.RawOrigin
	if err := json.Unmarshal(raw, &ro); err != nil {
		return nil, fmt.Errorf("unmarshal embedded origin: %w", err)
	}
	if ro.Hostname == "" {
		ro.Hostname = "_embedded"
	}
	compiled, err := config.CompileOrigin(&ro, sp)
	if err != nil {
		return nil, fmt.Errorf("compile embedded origin: %w", err)
	}
	return compiled, nil
}

func (sp *managerServiceProvider) HealthStatus(target string) plugin.HealthState {
	sp.healthMu.RLock()
	defer sp.healthMu.RUnlock()
	return sp.health[target]
}

func (sp *managerServiceProvider) SetHealthStatus(target string, state plugin.HealthState) {
	sp.healthMu.Lock()
	defer sp.healthMu.Unlock()
	sp.health[target] = state
}

// noopEventEmitter discards all events.
type noopEventEmitter struct{}

func (*noopEventEmitter) Emit(_ context.Context, _ string, _ map[string]any) error { return nil }
func (*noopEventEmitter) Enabled(_ string) bool                                    { return false }

// --- Origin Compilation and Atomic Swap ---

// compileAllOrigins reads inline origins from globalConfig.Origins, compiles
// each into a CompiledOrigin, and atomically swaps the entire map into the
// CompiledConfigManager. Origins that fail to compile are logged and skipped
// (partial success is preferred over total failure). The previous CompiledConfig
// snapshot is cleaned up after a grace period to allow in-flight requests to drain.
func (s *Service) compileAllOrigins() {
	if s.compiledCfg == nil {
		slog.Warn("compileAllOrigins: compiled config manager not initialized, skipping")
		return
	}

	origins := globalConfig.Origins
	if len(origins) == 0 {
		slog.Debug("compileAllOrigins: no inline origins to compile")
		return
	}

	startTime := time.Now()

	// Create (or reuse) the service provider. We create a new one each reload
	// so that the health map persists (it is stored on Service).
	sp := s.getOrCreateServiceProvider()

	compiled := make(map[string]*config.CompiledOrigin, len(origins))
	var skipped int

	for hostname, originMap := range origins {
		raw, err := originMapToRawOrigin(hostname, originMap)
		if err != nil {
			slog.Warn("compileAllOrigins: failed to convert origin config",
				"hostname", hostname, "error", err)
			skipped++
			continue
		}

		co, err := config.CompileOrigin(raw, sp)
		if err != nil {
			slog.Warn("compileAllOrigins: failed to compile origin",
				"hostname", hostname, "error", err)
			skipped++
			continue
		}

		compiled[hostname] = co
	}

	s.compiledCfg.Swap(config.NewCompiledConfig(compiled))

	duration := time.Since(startTime)
	slog.Info("compiled all inline origins",
		"total", len(origins),
		"compiled", len(compiled),
		"skipped", skipped,
		"duration_ms", duration.Milliseconds())
	metric.ConfigReloadWithDuration("compile_origins", duration)
}

// serviceProvider is the shared provider that persists health state across
// config reloads. Lazily created on first use.
func (s *Service) getOrCreateServiceProvider() *managerServiceProvider {
	if s.svcProvider != nil {
		return s.svcProvider
	}
	s.svcProvider = newManagerServiceProvider(s.manager, s.compiledCfg)
	return s.svcProvider
}

// originMapToRawOrigin converts a parsed YAML origin (map[string]any) into a
// RawOrigin via JSON round-trip. This approach leverages Go's json tags on
// RawOrigin to handle field mapping automatically, avoiding manual field-by-field
// assignment that would break when new fields are added.
func originMapToRawOrigin(hostname string, m map[string]any) (*config.RawOrigin, error) {
	// Ensure hostname is set in the map so it appears in the JSON.
	m["hostname"] = hostname

	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal origin %q: %w", hostname, err)
	}

	var raw config.RawOrigin
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal origin %q: %w", hostname, err)
	}

	// Fallback: ensure hostname is set even if the JSON key didn't map.
	if raw.Hostname == "" {
		raw.Hostname = hostname
	}

	return &raw, nil
}
