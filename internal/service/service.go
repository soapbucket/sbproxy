// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
//
// Startup sequence (see Service.Start):
//  1. Load config from disk (sb.yml + local origin files)
//  2. Initialize loggers (application, request, security)
//  3. Initialize pools, server variables, DNS cache
//  4. Create the Manager (storage, messenger, crypto, caches)
//  5. Initialize vaults, classifier, feature flags, host filter
//  6. Compile inline origins into the CompiledConfigManager
//  7. Build the HTTP router and start proxy servers (HTTP, HTTPS, HTTP/3)
//  8. Start message bus subscribers and hot-reload watcher
//  9. Set up signal handlers for graceful shutdown
package service

import (
	"github.com/soapbucket/sbproxy/internal/cache/response"
	"github.com/soapbucket/sbproxy/internal/security/tlsutil"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
	"github.com/soapbucket/sbproxy/internal/cache/store"

	"github.com/soapbucket/sbproxy/internal/embedded"
	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/httpkit/bufferpool"
	"github.com/soapbucket/sbproxy/internal/platform/servervar"
	"github.com/soapbucket/sbproxy/internal/vault"
	"github.com/soapbucket/sbproxy/internal/middleware/callback"
	"github.com/soapbucket/sbproxy/internal/loader/configloader"
	"github.com/soapbucket/sbproxy/internal/platform/dns"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/loader/featureflags"
	"github.com/soapbucket/sbproxy/internal/platform/health"
	"github.com/soapbucket/sbproxy/internal/security/hostfilter"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	luactx "github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/engine/middleware"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/loader/settings"
	"github.com/soapbucket/sbproxy/internal/security/signature"
	_ "github.com/soapbucket/sbproxy/internal/platform/storage" // Register storage drivers
	"github.com/soapbucket/sbproxy/internal/template"
	"github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/internal/version"
	"github.com/soapbucket/sbproxy/internal/httpkit/zerocopy"

	"github.com/soapbucket/sbproxy/internal/observe/telemetry"
	"golang.org/x/sync/errgroup"
)

// Service is the top-level proxy server. It owns the Manager, compiled config,
// and all server goroutines. The errgroup (g) runs HTTP/HTTPS/HTTP3/telemetry
// servers in parallel and propagates the first fatal error.
type Service struct {
	ConfigDir         string
	ConfigFile        string
	LogLevel          string
	RequestLogLevel   string
	GraceTime         int
	DisableHostFilter bool
	DisableSbFlags    bool

	ctx    context.Context
	cancel context.CancelFunc

	manager        manager.Manager
	callbackCache  *callback.CallbackCache
	reloadManager  *ReloadManager

	hostFilter     *hostfilter.HostFilter

	classifierMC   *classifier.ManagedClient   // Prompt classifier sidecar client

	// compiledCfg manages the atomic pointer to the current CompiledConfig.
	// The hot path (ServeHTTP) can use Load() for lock-free hostname lookup.
	// Populated during startup; updated on config reload via atomic Swap.
	compiledCfg    *CompiledConfigManager

	// svcProvider bridges the Manager to plugin.ServiceProvider for CompileOrigin.
	// Created once and reused so health state persists across reloads.
	svcProvider    *managerServiceProvider

	g errgroup.Group
}

// Option configures an optional service subsystem.
type Option func(*Service)




// WithClassifier enables the ML classifier sidecar.
func WithClassifier(mc *classifier.ManagedClient) Option {
	return func(s *Service) { s.classifierMC = mc }
}

// New creates a new service instance with optional subsystems.
func New(opts ...Option) *Service {
	s := &Service{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Start initializes and starts the service
func (s *Service) Start() error {
	startTime := time.Now()

	s.ctx, s.cancel = context.WithCancel(context.Background())

	healthManager := health.Initialize()

	if err := s.loadConfig(); err != nil {
		return err
	}

	s.initLoggers()

	// Log embedded data version
	ev := embedded.Version()
	slog.Info("embedded data loaded", "generated_at", ev.GeneratedAt, "files", len(ev.Files))

	s.initPools()
	s.initServerVariables()
	s.initConfigGetters()
	s.initDNS()
	s.initTelemetryProvider()
	if err := s.initManager(); err != nil {
		return err
	}

	s.initServerVaults()
	s.initClassifier()

	// Disable X-Sb-Flags header processing if configured (production mode)
	if s.DisableSbFlags {
		featureflags.SetDisabled(true)
		slog.Info("sb-flags disabled: X-Sb-Flags header and _sb.* query params will be ignored")
	}

	s.initFeatureFlags()
	s.initHostFilter()
	s.initCompiledConfig()

	s.initWorkspaceMode()
	s.initCacheAdmin()
	s.startTelemetryServer()

	router := s.buildRouter()
	s.startProxyServers(router)
	s.startSubscribers()

	startupTime := time.Since(startTime)
	healthManager.SetReady(true)

	s.initHotReload()
	s.setupGracefulShutdown(healthManager)

	slog.Info("service started", "startup_time", startupTime.String())
	return nil
}

// initPools initializes buffer pools, zerocopy, and token matcher factory.
func (s *Service) initPools() {
	bufferpool.InitBufferPools()
	slog.Debug("adaptive buffer pool initialized")

	zerocopy.InitBufferPools(bufferpool.GetAdaptivePool())

	cacher.SetAdaptivePoolGetter(func() interface{} {
		return bufferpool.GetAdaptivePool()
	})

	initTokenMatcherFactory()
}

// initServerVariables populates the server variables singleton from built-in
// values (version, hostname, etc.) and any operator-defined custom variables
// from the sb.yml "var" section.
func (s *Service) initServerVariables() {
	hostname, _ := os.Hostname()

	// Generate a short instance ID from hostname + PID
	instanceID := fmt.Sprintf("%s-%d", hostname, os.Getpid())

	env := globalConfig.OTelConfig.Environment
	if env == "" {
		env = "production"
	}

	startTimeStr := time.Now().UTC().Format(time.RFC3339)

	vars, err := servervar.BuildServerVariables(
		instanceID,
		version.Version,
		version.BuildHash,
		startTimeStr,
		hostname,
		env,
		globalConfig.Var,
	)
	if err != nil {
		slog.Warn("server variables initialization error", "error", err)
		return
	}

	servervar.SetServerVariables(vars)

	// Build and store the new ServerContext singleton
	sc, err := servervar.BuildServerContext(
		instanceID,
		version.Version,
		version.BuildHash,
		startTimeStr,
		hostname,
		env,
		globalConfig.Var,
	)
	if err != nil {
		slog.Warn("server context initialization error", "error", err)
	} else {
		servervar.SetServerContext(sc)
	}

	// Register the getter callback for template and Lua packages (avoids import cycles)
	template.SetServerVarsGetter(servervar.GetServerVariables)
	luactx.SetServerVarsGetter(servervar.GetServerVariables)

	slog.Debug("server variables initialized", "count", len(vars))
}

// loadConfig loads the service configuration from disk.
func (s *Service) loadConfig() error {
	// Initialize the config registry from init()-populated maps.
	// DefaultRegistry() copies all registered types into an explicit Registry,
	// making the production loading path use the Registry instead of bare maps.
	config.SetRegistry(config.DefaultRegistry())

	if err := LoadConfig(s.ConfigDir, s.ConfigFile); err != nil {
		slog.Error("error loading configuration", "error", err, "config_dir", s.ConfigDir, "config_file", s.ConfigFile)
		return err
	}
	return loadLocalOrigins()
}

// initLoggers initializes zap-based application, request, and security loggers.
func (s *Service) initLoggers() {
	appLogCfg := s.getApplicationLoggingConfig()
	_, appSlogLogger := logging.InitApplicationLoggerZap(appLogCfg)
	slog.SetDefault(appSlogLogger)
	slog.Info("service starting", "config_dir", s.ConfigDir, "config_file", s.ConfigFile, "log_level", s.LogLevel, "grace_time", s.GraceTime)

	reqLogCfg := s.getRequestLoggingConfig()
	logging.InitRequestLoggerZap(reqLogCfg)

	secLogCfg := s.getSecurityLoggingConfig()
	logging.InitSecurityLoggerZap(secLogCfg)
}

// initConfigGetters registers config getter functions that bridge import cycles.
// V2 compiled path uses transport.NewTransportFromConfig directly; these
// getters wire global coalescing config into the transport factory.
func (s *Service) initConfigGetters() {
	transport.SetGlobalHTTP2CoalescingGetter(func() transport.HTTP2CoalescingConfig {
		globalCfg := GetGlobalHTTP2CoalescingConfig()
		return transport.HTTP2CoalescingConfig{
			Enabled:                  !globalCfg.Disabled,
			MaxIdleConnsPerHost:      globalCfg.MaxIdleConnsPerHost,
			IdleConnTimeout:          globalCfg.IdleConnTimeout,
			MaxConnLifetime:          globalCfg.MaxConnLifetime,
			AllowIPBasedCoalescing:   globalCfg.AllowIPBasedCoalescing,
			AllowCertBasedCoalescing: globalCfg.AllowCertBasedCoalescing,
			StrictCertValidation:     globalCfg.StrictCertValidation,
		}
	})

	transport.SetGlobalRequestCoalescingGetter(func() transport.CoalescingConfig {
		globalCfg := GetGlobalRequestCoalescingConfig()
		cfg := transport.CoalescingConfig{
			Enabled:         globalCfg.Enabled,
			MaxInflight:     globalCfg.MaxInflight,
			CoalesceWindow:  globalCfg.CoalesceWindow,
			MaxWaiters:      globalCfg.MaxWaiters,
			CleanupInterval: globalCfg.CleanupInterval,
		}
		switch globalCfg.KeyStrategy {
		case "method_url":
			cfg.KeyFunc = transport.MethodURLKey
		default:
			cfg.KeyFunc = transport.DefaultCoalesceKey
		}
		return cfg
	})
}

// initDNS initializes the DNS cache resolver from global config.
// Wrapped with a 10-second timeout to prevent startup hangs.
func (s *Service) initDNS() {
	done := make(chan struct{})
	go func() {
		dns.InitGlobalResolver(dns.DNSCacheSettings{
			Enabled:           globalConfig.ProxyConfig.DNSCacheSettings.Enabled,
			MaxEntries:        globalConfig.ProxyConfig.DNSCacheSettings.MaxEntries,
			DefaultTTL:        globalConfig.ProxyConfig.DNSCacheSettings.DefaultTTL,
			NegativeTTL:       globalConfig.ProxyConfig.DNSCacheSettings.NegativeTTL,
			ServeStaleOnError: globalConfig.ProxyConfig.DNSCacheSettings.ServeStaleOnError,
			BackgroundRefresh: globalConfig.ProxyConfig.DNSCacheSettings.BackgroundRefresh,
		})
		close(done)
	}()

	dnsTimer := time.NewTimer(10 * time.Second)
	defer dnsTimer.Stop()
	select {
	case <-done:
		// DNS resolver initialized successfully
	case <-dnsTimer.C:
		slog.Warn("DNS resolver initialization timed out after 10s, continuing with default resolver")
	}
}

// initTelemetryProvider initializes OpenTelemetry tracing/metrics provider.
func (s *Service) initTelemetryProvider() {
	if err := initOTel(s.ctx); err != nil {
		slog.Error("error initializing OpenTelemetry", "error", err)
	}
}

// initManager creates the manager with all settings, callback cache, and capture manager.
func (s *Service) initManager() error {
	settings := manager.GlobalSettings{
		StorageSettings:   globalConfig.StorageSettings,
		MessengerSettings: globalConfig.MessengerSettings,
		CryptoSettings:    globalConfig.CryptoSettings,

		OriginLoaderSettings: manager.OriginLoaderSettings{
			MaxOriginRecursionDepth:   globalConfig.ProxyConfig.OriginLoaderSettings.MaxOriginRecursionDepth,
			MaxOriginForwardDepth:     globalConfig.ProxyConfig.OriginLoaderSettings.MaxOriginForwardDepth,
			OriginCacheTTL:            globalConfig.ProxyConfig.OriginLoaderSettings.OriginCacheTTL,
			HostnameFallback:          globalConfig.ProxyConfig.OriginLoaderSettings.HostnameFallback,
			HostFilterEnabled:         globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterEnabled,
			HostFilterEstimatedItems:  globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterEstimatedItems,
			HostFilterFPRate:          globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterFPRate,
			HostFilterRebuildInterval: globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterRebuildInterval,
			HostFilterRebuildJitter:   globalConfig.ProxyConfig.OriginLoaderSettings.HostFilterRebuildJitter,
		},

		CacherSettings: func() map[manager.CacheLevel]cacher.Settings {
			l1 := globalConfig.L1CacheSettings
			if l1.Driver == "" {
				l1.Driver = "memory"
				if l1.Params == nil {
					l1.Params = make(map[string]string)
				}
				if l1.Params["max_size"] == "" {
					l1.Params["max_size"] = "104857600" // 100MB default
				}
			}
			return map[manager.CacheLevel]cacher.Settings{
				manager.L1Cache: l1,
				manager.L2Cache: globalConfig.L2CacheSettings,
				manager.L3Cache: globalConfig.L3CacheSettings,
			}
		}(),

		CookieSettings: manager.CookieSettings{
			SessionCookieName: globalConfig.ProxyConfig.SessionCacherSettings.SessionCookieName,
			SessionMaxAge:     globalConfig.ProxyConfig.SessionCacherSettings.SessionMaxAge,
			StickyCookieName:  globalConfig.ProxyConfig.StickyCookieSettings.StickyCookieName,
		},

		HTTP3Settings: manager.HTTP3Settings{
			EnableHTTP3:   globalConfig.ProxyConfig.EnableHTTP3,
			HTTP3BindPort: globalConfig.ProxyConfig.HTTP3BindPort,
		},

		DebugSettings: manager.DebugSettings{
			Debug:          globalConfig.ProxyConfig.DebugSettings.Debug,
			DisplayHeaders: globalConfig.ProxyConfig.DebugSettings.DisplayHeaders,
		},

		CompressionLevel:  globalConfig.ProxyConfig.CompressionLevel,
		L2CacheTimeout:    globalConfig.ProxyConfig.SessionCacherSettings.L2CacheTimeout,
		MaxRecursionDepth: globalConfig.ProxyConfig.MaxRecursionDepth,
	}

	m, err := manager.NewManager(s.ctx, settings)
	if err != nil {
		slog.Error("error initializing manager", "error", err)
		return err
	}
	s.manager = m

	s.callbackCache = callback.NewCallbackCache(m.GetCache(manager.L2Cache))
	slog.Info("initialized callback cache with L2 (distributed)")

	// Initialize events bus
	if globalConfig.EventSettings.Driver != "" {
		eventBus, err := messenger.NewMessenger(globalConfig.EventSettings)
		if err != nil {
			slog.Error("failed to initialize event bus", "error", err)
		} else {
			channelPrefix := "sb:events"
			if p, ok := globalConfig.EventSettings.Params["channel_prefix"]; ok {
				channelPrefix = p
			}
			events.Init(eventBus, channelPrefix)
			slog.Info("initialized event bus", "driver", globalConfig.EventSettings.Driver, "prefix", channelPrefix)
		}
	}

	return nil
}

// initServerVaults registers server-level vault definitions from sb.yaml
// so they are available to all origins via MergeVaults at config-load time.
func (s *Service) initServerVaults() {
	defs := globalConfig.ProxyConfig.Vaults
	if len(defs) == 0 {
		return
	}
	vault.SetServerVaults(defs)
	slog.Info("server-level vaults configured", "count", len(defs))
}

// initClassifier connects to the prompt-classifier sidecar if configured.
// When fail_open is true and the sidecar is unreachable, the proxy starts
// normally and downstream features degrade gracefully.
func (s *Service) initClassifier() {
	settings := globalConfig.ClassifierSettings
	if !settings.IsEnabled() {
		return
	}

	mc, err := classifier.NewManagedClient(s.ctx, settings)
	if err != nil {
		if settings.FailOpen {
			slog.Warn("classifier sidecar unavailable, continuing without it",
				"address", settings.Address, "error", err)
			return
		}
		slog.Error("classifier sidecar required but unavailable", "address", settings.Address, "error", err)
		os.Exit(1)
	}

	s.classifierMC = mc
	classifier.SetGlobal(mc)

	ts := classifier.NewTenantSync(mc)
	classifier.SetGlobalSync(ts)

	// Fetch sidecar version info for the startup log
	ver, verErr := mc.Version()
	if verErr != nil {
		slog.Info("classifier sidecar connected",
			"address", settings.Address,
			"embed_supported", mc.IsEmbedSupported(),
		)
	} else {
		slog.Info("classifier sidecar connected",
			"address", settings.Address,
			"name", ver.Name,
			"version", ver.Version,
			"mode", ver.Mode,
			"embed_supported", ver.EmbedSupported,
		)
	}
}

// initFeatureFlags creates the feature flag manager if enabled and registers
// getter callbacks for the template and Lua packages.
func (s *Service) initFeatureFlags() {
	cfg := globalConfig.FeatureFlags
	if !cfg.Enabled {
		slog.Info("feature flags disabled")
		return
	}

	ffCfg := featureflags.Config{
		SyncTopic:     cfg.SyncTopic,
		CacheTTL:      cfg.CacheTTL,
		DefaultValues: cfg.DefaultValues,
	}

	var msg messenger.Messenger
	if s.manager != nil {
		msg = s.manager.GetMessenger()
	}

	cm, err := featureflags.NewCacheManager(s.ctx, ffCfg, msg)
	if err != nil {
		slog.Error("failed to initialize feature flag manager", "error", err)
		return
	}

	featureflags.SetGlobalManager(cm)

	// Register getter callbacks (avoids import cycles)
	template.SetFeatureFlagGetter(featureflags.GlobalGetFlags)
	luactx.SetFeatureFlagGetter(featureflags.GlobalGetFlags)

	slog.Info("feature flag manager initialized", "sync_topic", cfg.SyncTopic)
}

// initHostFilter initializes the bloom filter for hostname pre-checking.
func (s *Service) initHostFilter() {
	filterSettings := globalConfig.ProxyConfig.OriginLoaderSettings
	if !filterSettings.HostFilterEnabled || s.DisableHostFilter {
		slog.Info("host filter disabled")
		return
	}

	hf := hostfilter.New(
		uint(filterSettings.HostFilterEstimatedItems),
		filterSettings.HostFilterFPRate,
	)

	wsSettings := settings.Global
	if wsSettings.IsDedicatedMode() {
		hf.SetWorkspaceID(wsSettings.WorkspaceID)
		configloader.DefaultLoader().SetWorkspaceID(wsSettings.WorkspaceID)
		slog.Info("dedicated workspace mode enabled",
			"workspace_id", wsSettings.WorkspaceID)
	}

	var hostnames []string
	var err error
	if wsSettings.IsDedicatedMode() {
		hostnames, err = hostfilter.LoadHostnamesByWorkspace(s.ctx, s.manager.GetStorage(), wsSettings.WorkspaceID)
	} else {
		hostnames, err = hostfilter.LoadHostnames(s.ctx, s.manager.GetStorage())
	}
	if err != nil {
		slog.Warn("failed to load hostnames for host filter, filter disabled", "error", err)
		return
	}

	// If storage returned no hostnames but we have inline origins, seed from config
	if len(hostnames) == 0 && len(globalConfig.Origins) > 0 {
		for hostname := range globalConfig.Origins {
			hostnames = append(hostnames, hostname)
		}
		slog.Info("host filter seeded from inline origins", "hostname_count", len(hostnames))
	}

	hf.Reload(hostnames)
	configloader.DefaultLoader().SetHostFilter(hf)
	s.hostFilter = hf
	slog.Info("host filter initialized", "hostname_count", len(hostnames), "workspace_mode", wsSettings.WorkspaceMode)

	hf.StartPeriodicRebuild(
		s.ctx,
		s.manager.GetStorage(),
		filterSettings.HostFilterRebuildInterval,
		filterSettings.HostFilterRebuildJitter,
	)
}


// initCompiledConfig initializes the CompiledConfigManager and populates it
// with compiled inline origins from the configuration file (sb.yml).
func (s *Service) initCompiledConfig() {
	s.compiledCfg = NewCompiledConfigManager(DefaultGracePeriod)
	slog.Info("compiled config manager initialized", "grace_period", DefaultGracePeriod)

	// Compile inline origins (if any). Errors are logged per-origin.
	s.compileAllOrigins()
}

// GetCompiledConfigManager returns the compiled config manager, which provides
// lock-free hostname lookup on the hot path. Returns nil if not yet initialized.
func (s *Service) GetCompiledConfigManager() *CompiledConfigManager {
	return s.compiledCfg
}

// initWorkspaceMode sets the workspace mode Prometheus info metric.
func (s *Service) initWorkspaceMode() {
	ws := settings.Global
	metric.SetWorkspaceMode(ws.WorkspaceMode, ws.WorkspaceID)
	if ws.IsDedicatedMode() {
		slog.Info("proxy running in dedicated workspace mode",
			"workspace_id", ws.WorkspaceID)
	} else {
		slog.Info("proxy running in shared workspace mode")
	}
}


// initCacheAdmin creates the CacheWarmer, CacheInvalidator, and CacheAdminAPI,
// then registers the admin routes on the telemetry router so they are served on
// the internal telemetry port (not on the main proxy port).
func (s *Service) initCacheAdmin() {
	warmer := responsecache.NewCacheWarmer(responsecache.DefaultCacheWarmerConfig())

	// Wire caches into the warmer
	if s.callbackCache != nil {
		warmer.SetCallbackCache(s.callbackCache)
	}
	if l1 := s.manager.GetCache(manager.L1Cache); l1 != nil {
		warmer.SetResponseCache(l1)
	}

	invalidator := responsecache.NewCacheInvalidator(
		s.manager.GetCache(manager.L1Cache),
		s.manager.GetCache(manager.L2Cache),
		s.manager.GetCache(manager.L3Cache),
	)

	// Use a simple admin key from the security config (or empty to disable auth).
	adminKey := globalConfig.Security.AdminAPIKey
	api := responsecache.NewCacheAdminAPI(warmer, invalidator, adminKey)

	// Register cache admin routes on the telemetry router (internal port only).
	telemetry.RegisterAdminRoutes(func(router chi.Router) {
		api.RegisterChiRoutes(router)
	})

	slog.Info("cache admin API initialized on telemetry server")
}

// startTelemetryServer starts the telemetry/metrics HTTP server if configured.
func (s *Service) startTelemetryServer() {
	telemetryConf := telemetry.Config{
		BindAddress:        globalConfig.TelemetryConfig.BindAddress,
		BindPort:           globalConfig.TelemetryConfig.BindPort,
		TLSCert:            globalConfig.TelemetryConfig.TLSCert,
		TLSKey:             globalConfig.TelemetryConfig.TLSKey,
		CertificateFile:    globalConfig.TelemetryConfig.CertificateFile,
		CertificateKeyFile: globalConfig.TelemetryConfig.CertificateKeyFile,
		EnableProfiler:     globalConfig.TelemetryConfig.EnableProfiler,
		MinTLSVersion:      globalConfig.TelemetryConfig.MinTLSVersion,
		TLSCipherSuites:    globalConfig.TelemetryConfig.TLSCipherSuites,
	}

	if telemetry.ShouldBind(telemetryConf) {
		slog.Info("starting telemetry service", "address", telemetryConf.BindAddress, "port", telemetryConf.BindPort)
		s.g.Go(func() error {
			if err := telemetry.Initialize(telemetryConf, s.ctx, s.ConfigDir); err != nil {
				if err == http.ErrServerClosed {
					return nil
				}
				slog.Error("could not start telemetry server", "error", err, "address", telemetryConf.BindAddress, "port", telemetryConf.BindPort)
				return err
			}
			return nil
		})
	} else {
		slog.Debug("telemetry server not started, no bind_port configured")
	}
}

// buildRouter creates the HTTP router with middleware chain.
func (s *Service) buildRouter() *chi.Mux {
	routerOpts := middleware.RouterOptions{
		AdminKey:    globalConfig.Security.AdminAPIKey,
		CompiledCfg: s.compiledCfg,
		Loader:      configloader.DefaultLoader(),
		SvcProvider: s.svcProvider,
	}
	return middleware.Router(s.manager, routerOpts)
}

// startProxyServers starts HTTP, HTTPS, and HTTP/3 proxy servers as configured.
func (s *Service) startProxyServers(router *chi.Mux) {
	m := s.manager

	if ShouldBindHTTP(globalConfig) {
		slog.Info("starting HTTP proxy service", "address", globalConfig.ProxyConfig.BindAddress, "port", globalConfig.ProxyConfig.HTTPBindPort)
		s.g.Go(func() error {
			if err := StartHTTP(globalConfig.ProxyConfig, m, s.callbackCache, router); err != nil {
				slog.Error("could not start proxy http server", "error", err, "address", globalConfig.ProxyConfig.BindAddress, "port", globalConfig.ProxyConfig.HTTPBindPort)
				return err
			}
			return nil
		})
	} else {
		slog.Warn("proxy http server not started, disabled in config file")
	}

	tlsConfig := s.buildTLSConfig()

	if tlsConfig != nil {
		checkInterval := 1 * time.Hour
		_ = MonitorServerCertificates(s.ctx, tlsConfig, checkInterval)
		slog.Info("started TLS certificate expiration monitoring", "check_interval", checkInterval)
	}

	acmeStatus := "disabled"
	if globalConfig.ProxyConfig.CertificateSettings.UseACME {
		acmeStatus = fmt.Sprintf("enabled (email: %s, domains: %v)", globalConfig.ProxyConfig.CertificateSettings.ACMEEmail, globalConfig.ProxyConfig.CertificateSettings.ACMEDomains)
	}

	if ShouldBindHTTPS(globalConfig) {
		slog.Info("starting HTTPS proxy service", "address", globalConfig.ProxyConfig.BindAddress, "port", globalConfig.ProxyConfig.HTTPSBindPort, "acme", acmeStatus)
		s.g.Go(func() error {
			if err := StartHTTPS(globalConfig.ProxyConfig, m, s.callbackCache, tlsConfig, router); err != nil {
				slog.Error("could not start proxy https server", "error", err, "address", globalConfig.ProxyConfig.BindAddress, "port", globalConfig.ProxyConfig.HTTPSBindPort)
				return err
			}
			return nil
		})
	} else {
		slog.Warn("proxy https server not started, disabled in config file")
	}

	if ShouldBindHTTP3(globalConfig) {
		http3Port := globalConfig.ProxyConfig.HTTPSBindPort
		if globalConfig.ProxyConfig.HTTP3BindPort > 0 {
			http3Port = globalConfig.ProxyConfig.HTTP3BindPort
		}
		slog.Info("starting HTTP/3 proxy service", "address", globalConfig.ProxyConfig.BindAddress, "port", http3Port)
		s.g.Go(func() error {
			if err := StartHTTP3(globalConfig.ProxyConfig, m, s.callbackCache, tlsConfig, router); err != nil {
				slog.Error("could not start proxy http/3 server", "error", err, "address", globalConfig.ProxyConfig.BindAddress, "port", http3Port)
				return err
			}
			return nil
		})
	} else {
		slog.Warn("proxy http/3 server not started, disabled in config file")
	}

	if ShouldBindHTTPSProxy(globalConfig.HTTPSProxyConfig) {
		slog.Info("starting HTTPS proxy authentication service", "port", globalConfig.HTTPSProxyConfig.Port, "hostname", globalConfig.HTTPSProxyConfig.Hostname)
		s.g.Go(func() error {
			if err := StartHTTPSProxyServer(globalConfig.HTTPSProxyConfig, m); err != nil {
				slog.Error("could not start HTTPS proxy auth server", "error", err, "port", globalConfig.HTTPSProxyConfig.Port)
				return err
			}
			return nil
		})
	} else {
		slog.Debug("HTTPS proxy auth server not started, disabled or not fully configured")
	}

}

// buildTLSConfig creates the TLS configuration for HTTPS/HTTP3 servers.
func (s *Service) buildTLSConfig() *tls.Config {
	if globalConfig.ProxyConfig.CertificateSettings.UseACME {
		l3Cache := s.manager.GetCache(manager.L3Cache)
		tlsConfig := GetACMETLSConfig(s.ctx, globalConfig, s.ConfigDir, l3Cache)

		if len(globalConfig.ProxyConfig.CertificateSettings.ACMEDomains) > 0 {
			if err := PreManageACMEDomains(s.ctx, globalConfig.ProxyConfig.CertificateSettings.ACMEDomains); err != nil {
				slog.Warn("failed to pre-manage ACME certificates, will attempt on-demand",
					"error", err,
					"domains", globalConfig.ProxyConfig.CertificateSettings.ACMEDomains)
			}
		}
		// Apply mTLS client authentication if configured
		applyClientAuth(tlsConfig, globalConfig.ProxyConfig.CertificateSettings)
		return tlsConfig
	}

	nextProtos := []string{"h2", "http/1.1"}
	if globalConfig.ProxyConfig.EnableHTTP3 {
		nextProtos = []string{"h3", "h2", "http/1.1"}
	}

	minTLSVersion := tlsutil.GetTLSVersion(globalConfig.ProxyConfig.CertificateSettings.MinTLSVersion)
	tlsConfig := &tls.Config{
		GetCertificate:           getDynamicCertificate(globalConfig, s.ConfigDir),
		MinVersion:               minTLSVersion,
		NextProtos:               nextProtos,
		CipherSuites:             tlsutil.GetTLSCiphersFromNames(globalConfig.ProxyConfig.CertificateSettings.TLSCipherSuites),
		PreferServerCipherSuites: true,
	}

	// Apply mTLS client authentication if configured
	applyClientAuth(tlsConfig, globalConfig.ProxyConfig.CertificateSettings)

	tlsVersionStr := "1.2"
	if minTLSVersion == tls.VersionTLS13 {
		tlsVersionStr = "1.3"
	}
	slog.Info("TLS configuration for proxy service",
		"min_tls_version", tlsVersionStr,
		"configured_value", globalConfig.ProxyConfig.CertificateSettings.MinTLSVersion)

	return tlsConfig
}

// startSubscribers starts all message bus subscribers for cache refresh and expiration.
// Subscribers are disabled when ConfigSyncMode is "pull" (REST-only mode for private clusters).
func (s *Service) startSubscribers() {
	m := s.manager

	if globalConfig.ProxyConfig.ConfigSyncMode == "pull" {
		slog.Info("config sync mode is pull, skipping all message bus subscribers")
		return
	}

	if globalConfig.ProxyConfig.EnableOriginCacheRefresh {
		topic := globalConfig.ProxyConfig.OriginCacheRefreshTopic
		if topic == "" {
			topic = "origin_cache_refresh"
		}
		if err := configloader.StartOriginCacheRefreshSubscriber(s.ctx, m, topic); err != nil {
			slog.Error("failed to start origin cache refresh subscriber", "error", err)
		}
	}

	if globalConfig.ProxyConfig.EnableProxyConfigChanges {
		topic := globalConfig.ProxyConfig.ProxyConfigChangesTopic
		if topic == "" {
			topic = "proxy-config-changes"
		}
		if err := configloader.StartOriginCacheRefreshSubscriber(s.ctx, m, topic); err != nil {
			slog.Error("failed to start proxy config changes subscriber", "error", err)
		}
	}

	if s.hostFilter != nil && globalConfig.ProxyConfig.EnableProxyConfigChanges {
		topic := globalConfig.ProxyConfig.ProxyConfigChangesTopic
		if topic == "" {
			topic = "proxy-config-changes"
		}
		if err := hostfilter.StartHostFilterSubscriber(s.ctx, m, s.hostFilter, topic); err != nil {
			slog.Error("failed to start host filter subscriber", "error", err)
		}
	}

	if globalConfig.ProxyConfig.EnableResponseCacheExpiration {
		topic := globalConfig.ProxyConfig.ResponseCacheExpirationTopic
		if topic == "" {
			topic = "response_cache_expiration"
		}
		expirationConfig := responsecache.ResponseCacheExpirationConfig{
			Enabled:       true,
			NormalizeURL:  globalConfig.ProxyConfig.ResponseCacheNormalizeURL,
			NormalizePath: globalConfig.ProxyConfig.ResponseCacheNormalizePath,
			DefaultMethod: globalConfig.ProxyConfig.ResponseCacheDefaultMethod,
		}
		if err := responsecache.StartResponseCacheExpirationSubscriber(s.ctx, m, topic, expirationConfig); err != nil {
			slog.Error("failed to start response cache expiration subscriber", "error", err)
		}
	}

	if globalConfig.ProxyConfig.EnableSignatureCacheExpiration {
		topic := globalConfig.ProxyConfig.SignatureCacheExpirationTopic
		if topic == "" {
			topic = "signature_cache_expiration"
		}
		expirationConfig := signature.SignatureCacheExpirationConfig{
			Enabled:       true,
			NormalizeURL:  globalConfig.ProxyConfig.SignatureCacheNormalizeURL,
			NormalizePath: globalConfig.ProxyConfig.SignatureCacheNormalizePath,
			DefaultMethod: globalConfig.ProxyConfig.SignatureCacheDefaultMethod,
		}
		if err := signature.StartSignatureCacheExpirationSubscriber(s.ctx, m, topic, expirationConfig); err != nil {
			slog.Error("failed to start signature cache expiration subscriber", "error", err)
		}
	}
}

// initHotReload initializes and starts the configuration hot reload manager.
func (s *Service) initHotReload() {
	reloadManager, err := NewReloadManager(s.ctx, s.ConfigDir, s.ConfigFile)
	if err != nil {
		slog.Error("failed to initialize config reload manager", "error", err)
		return
	}
	s.reloadManager = reloadManager

	// Recompile all inline origins whenever the config is hot-reloaded.
	s.reloadManager.OnReload(func() {
		transport.CleanTransportCache()
		s.compileAllOrigins()
	})

	if err := s.reloadManager.Start(); err != nil {
		slog.Error("failed to start config reload manager", "error", err)
	}
}

// setupGracefulShutdown registers signal handlers for graceful shutdown.
func (s *Service) setupGracefulShutdown(healthManager *health.Manager) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go s.handleShutdownSignal(sigChan, healthManager)
}

// Wait blocks until the service is shut down
func (s *Service) Wait() error {
	return s.g.Wait()
}

// handleShutdownSignal handles OS signals for graceful shutdown
func (s *Service) handleShutdownSignal(sigChan chan os.Signal, healthManager *health.Manager) {
	// Wait for shutdown signal
	sig := <-sigChan
	slog.Info("received shutdown signal, initiating graceful shutdown",
		"signal", sig.String())

	// Mark service as shutting down (this will cause /ready to return 503)
	healthManager.SetShuttingDown(true)
	healthManager.SetReady(false)

	// Determine grace time for waiting on in-flight requests
	graceTime := time.Duration(s.GraceTime) * time.Second
	if graceTime == 0 {
		graceTime = 30 * time.Second // Default to 30 seconds
		slog.Info("using default grace time",
			"grace_time_seconds", 30)
	}

	// Wait for in-flight requests to complete with timeout
	slog.Info("waiting for in-flight requests to complete",
		"grace_time", graceTime,
		"initial_inflight_count", healthManager.GetInflightCount())

	deadline := time.Now().Add(graceTime)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	deadlineTimer := time.NewTimer(graceTime)
	defer deadlineTimer.Stop()

	for {
		inflightCount := healthManager.GetInflightCount()
		if inflightCount == 0 {
			slog.Info("all in-flight requests completed")
			break
		}

		if time.Now().After(deadline) {
			slog.Warn("grace time expired with in-flight requests remaining",
				"remaining_requests", inflightCount)
			break
		}

		slog.Debug("waiting for in-flight requests",
			"inflight_count", inflightCount,
			"time_remaining", time.Until(deadline).Round(time.Second))

		select {
		case <-ticker.C:
			// Continue waiting
		case <-deadlineTimer.C:
			// Timeout reached
			slog.Warn("shutdown grace time expired",
				"remaining_requests", healthManager.GetInflightCount())
			break
		}
	}

	// Now trigger the actual shutdown
	slog.Info("initiating server shutdown")
	s.Stop()
}

// Stop gracefully shuts down the service. Shutdown is orderly with a
// 10-second deadline for background component cleanup.
func (s *Service) Stop() {
	slog.Info("stopping service", "grace_time", s.GraceTime)
	stopTime := time.Now()

	// Create a 10-second shutdown deadline for background component cleanup
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// --- Phase 1: Stop subscribers and reload watchers ---

	slog.Info("shutdown phase 1: stopping subscribers and watchers")

	if s.reloadManager != nil {
		slog.Info("stopping config reload manager")
		s.reloadManager.Stop()
	}

	// Drain subscribers with a 5-second timeout to avoid blocking shutdown
	subscriberDone := make(chan struct{})
	go func() {
		slog.Info("stopping origin cache refresh subscriber")
		configloader.StopOriginCacheRefreshSubscriber()

		if s.hostFilter != nil {
			slog.Info("stopping host filter")
			s.hostFilter.Stop()
		}
		hostfilter.StopHostFilterSubscriber()

		slog.Info("stopping response cache expiration subscriber")
		responsecache.StopResponseCacheExpirationSubscriber()

		slog.Info("stopping signature cache expiration subscriber")
		signature.StopSignatureCacheExpirationSubscriber()

		close(subscriberDone)
	}()

	subscriberTimer := time.NewTimer(5 * time.Second)
	select {
	case <-subscriberDone:
		slog.Info("all subscribers drained cleanly")
	case <-subscriberTimer.C:
		slog.Warn("subscriber drain timeout after 5s, proceeding with shutdown")
	}
	subscriberTimer.Stop()

	// Mark service as not ready, not live, and shutting down
	healthManager := health.GetManager()
	healthManager.SetShuttingDown(true)
	healthManager.SetReady(false)
	healthManager.SetLive(false)

	// --- Phase 2: Stop background components (flush data before context cancel) ---

	slog.Info("shutdown phase 2: stopping background components")

	// Close classifier sidecar connection pool
	if s.classifierMC != nil {
		slog.Info("closing classifier sidecar client")
		s.classifierMC.Close()
	}

	// Stop DNS resolver background goroutines (cache refresh loop and metrics reporting)
	slog.Info("stopping DNS resolver")
	dns.StopGlobalResolver()

	// Stop global event bus (drain buffered events)
	slog.Info("stopping global event bus")
	if err := events.CloseGlobalBus(); err != nil {
		slog.Error("error closing global event bus", "error", err)
	}

	// --- Phase 3: Cancel service context to propagate to all per-config goroutines ---
	// This stops DDoS cleanup, IP filter cleanup, health checks, and any other
	// goroutines that received s.ctx.

	slog.Info("shutdown phase 3: cancelling service context")
	if s.cancel != nil {
		s.cancel()
	}

	// --- Phase 4: Parallel cleanup of remaining components with deadline ---

	slog.Info("shutdown phase 4: cleaning up remaining components")
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("shutting down OpenTelemetry")
		if err := shutdownOTel(); err != nil {
			slog.Error("error shutting down OpenTelemetry", "error", err)
		}
	}()

	if s.manager != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("closing server manager")
			s.manager.Close()
		}()
	}

	// Wait for parallel cleanup with the shutdown deadline
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("all background components stopped cleanly")
	case <-shutdownCtx.Done():
		slog.Warn("shutdown deadline exceeded, some components may not have stopped cleanly")
	}

	// --- Phase 5: Final synchronous cleanup ---

	slog.Info("shutting down adaptive buffer pool")
	bufferpool.ShutdownBufferPools()

	// Clean up extracted embedded data files
	embedded.Cleanup()

	// Flush and close all log output backends (ClickHouse, etc.)
	logging.Shutdown()

	shutdownTime := time.Since(stopTime)
	slog.Info("service stopped", "shutdown_time", shutdownTime)
}

// initTokenMatcherFactory initializes the factory function for creating token matchers
// This wires up the CEL package's NewTokenMatcher function so that HTML matchers
// can use CEL expressions without creating a circular import dependency
func initTokenMatcherFactory() {
	reqctx.SetTokenMatcherFactory(cel.NewTokenMatcher)
	slog.Debug("token matcher factory initialized")
}


// getApplicationLoggingConfig builds ApplicationLoggingConfig from the service config.
func (s *Service) getApplicationLoggingConfig() logging.ApplicationLoggingConfig {
	logCfg := globalConfig.ProxyConfig.LoggingConfig
	if logCfg.Application != nil {
		cfg := *logCfg.Application
		// CLI flag overrides config file
		if s.LogLevel != "" {
			cfg.Level = s.LogLevel
		}
		return cfg
	}
	cfg := logging.DefaultApplicationLoggingConfig()
	if s.LogLevel != "" {
		cfg.Level = s.LogLevel
	}
	return cfg
}

// getRequestLoggingConfig builds RequestLoggingConfig from the service config.
func (s *Service) getRequestLoggingConfig() logging.RequestLoggingConfig {
	logCfg := globalConfig.ProxyConfig.LoggingConfig
	if logCfg.Request != nil {
		cfg := *logCfg.Request
		// CLI flags override config file
		if s.RequestLogLevel != "" {
			cfg.Level = s.RequestLogLevel
		} else if s.LogLevel != "" {
			cfg.Level = s.LogLevel
		}
		if cfg.Level == "none" || cfg.Level == "off" {
			cfg.Enabled = false
		}
		return cfg
	}
	cfg := logging.DefaultRequestLoggingConfig()
	if s.RequestLogLevel != "" {
		cfg.Level = s.RequestLogLevel
	} else if s.LogLevel != "" {
		cfg.Level = s.LogLevel
	}
	if cfg.Level == "none" || cfg.Level == "off" {
		cfg.Enabled = false
	}
	return cfg
}

// getSecurityLoggingConfig builds SecurityLoggingConfig from the service config.
func (s *Service) getSecurityLoggingConfig() logging.SecurityLoggingConfig {
	logCfg := globalConfig.ProxyConfig.LoggingConfig
	if logCfg.Security != nil {
		cfg := *logCfg.Security
		// CLI flag overrides config file
		if s.LogLevel != "" {
			cfg.Level = s.LogLevel
		}
		return cfg
	}
	cfg := logging.DefaultSecurityLoggingConfig()
	if s.LogLevel != "" {
		cfg.Level = s.LogLevel
	}
	return cfg
}
