// Package settings manages runtime proxy settings and configuration defaults.
package settings

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// WorkspaceMode constants for proxy deployment topology.
const (
	// WorkspaceModeShared is a constant for workspace mode shared.
	WorkspaceModeShared = "shared"
	// WorkspaceModeDedicated is a constant for workspace mode dedicated.
	WorkspaceModeDedicated = "dedicated"
)

// ProcessSettings holds process-wide defaults loadable from environment variables.
// All settings are configured at startup and should be treated as read-only at runtime.
//
// Note: this type was renamed from GlobalSettings to avoid confusion with
// manager.GlobalSettings, which holds per-config runtime settings (cacher, storage, etc.).
type ProcessSettings struct {
	// Body size limits (bytes)
	MaxCoalesceBodyBytes int64 // SB_MAX_COALESCE_BODY, default 10MB
	MaxJWKSBodyBytes     int64 // SB_MAX_JWKS_BODY, default 1MB
	MaxRetryBodyBytes    int64 // SB_MAX_RETRY_BODY, default 32MB
	MaxCallbackBodyBytes int64 // SB_MAX_CALLBACK_BODY, default 10MB

	// Trusted proxy CIDRs for IP spoofing prevention
	TrustedProxyCIDRs []string // SB_TRUSTED_PROXIES (comma-separated), default []

	// Per-workspace quotas
	WorkspaceMaxCachedConfigs    int // SB_WS_MAX_CONFIGS, default 1000
	WorkspaceMaxRateLimitEntries int // SB_WS_MAX_RATE_ENTRIES, default 10000
	WorkspaceMaxSessions         int // SB_WS_MAX_SESSIONS, default 10000
	WorkspaceMaxEventSubs        int // SB_WS_MAX_EVENT_SUBS, default 100
	WorkspaceMaxCallbacks        int // SB_WS_MAX_CALLBACKS, default 50
	WorkspaceMaxEventHandlers    int // SB_WS_MAX_EVENT_HANDLERS, default 32

	// Workspace container isolation mode
	WorkspaceMode string // SB_WORKSPACE_MODE: "shared" (default) or "dedicated"
	WorkspaceID   string // SB_WORKSPACE_ID: required when WorkspaceMode is "dedicated"

	// Security: TLS verification enforcement
	// When true, per-origin skip_tls_verify is ignored and TLS verification is always enforced.
	// This prevents disabling certificate checks in production environments.
	EnforceTLSVerify bool // SB_ENFORCE_TLS_VERIFY, default false
}

// IsDedicatedMode returns true when this proxy instance serves a single workspace.
func (g *ProcessSettings) IsDedicatedMode() bool {
	return g.WorkspaceMode == WorkspaceModeDedicated && g.WorkspaceID != ""
}

// Global is the singleton process-wide settings instance.
// Initialized at startup via init().
var Global ProcessSettings

func init() {
	Global = ProcessSettings{
		// Body size limits
		MaxCoalesceBodyBytes: getEnvInt64("SB_MAX_COALESCE_BODY", 10*1024*1024), // 10 MB
		MaxJWKSBodyBytes:     getEnvInt64("SB_MAX_JWKS_BODY", 1*1024*1024),      // 1 MB
		MaxRetryBodyBytes:    getEnvInt64("SB_MAX_RETRY_BODY", 32*1024*1024),    // 32 MB
		MaxCallbackBodyBytes: getEnvInt64("SB_MAX_CALLBACK_BODY", 10*1024*1024), // 10 MB

		// Trusted proxies
		TrustedProxyCIDRs: getEnvStringSlice("SB_TRUSTED_PROXIES", []string{}),

		// Per-workspace quotas
		WorkspaceMaxCachedConfigs:    getEnvInt("SB_WS_MAX_CONFIGS", 1000),
		WorkspaceMaxRateLimitEntries: getEnvInt("SB_WS_MAX_RATE_ENTRIES", 10000),
		WorkspaceMaxSessions:         getEnvInt("SB_WS_MAX_SESSIONS", 10000),
		WorkspaceMaxEventSubs:        getEnvInt("SB_WS_MAX_EVENT_SUBS", 100),
		WorkspaceMaxCallbacks:        getEnvInt("SB_WS_MAX_CALLBACKS", 50),
		WorkspaceMaxEventHandlers:    getEnvInt("SB_WS_MAX_EVENT_HANDLERS", 32),

		WorkspaceMode: getEnvString("SB_WORKSPACE_MODE", WorkspaceModeShared),
		WorkspaceID:   getEnvString("SB_WORKSPACE_ID", ""),

		EnforceTLSVerify: getEnvBool("SB_ENFORCE_TLS_VERIFY", false),
	}

	if Global.WorkspaceMode == WorkspaceModeDedicated && Global.WorkspaceID == "" {
		slog.Error("SB_WORKSPACE_MODE is 'dedicated' but SB_WORKSPACE_ID is not set")
		os.Exit(1)
	}

	slog.Debug("global settings loaded",
		"max_coalesce_body_mb", Global.MaxCoalesceBodyBytes/(1024*1024),
		"max_jwks_body_mb", Global.MaxJWKSBodyBytes/(1024*1024),
		"max_retry_body_mb", Global.MaxRetryBodyBytes/(1024*1024),
		"max_callback_body_mb", Global.MaxCallbackBodyBytes/(1024*1024),
		"trusted_proxies_count", len(Global.TrustedProxyCIDRs),
		"ws_max_configs", Global.WorkspaceMaxCachedConfigs,
		"ws_max_rate_entries", Global.WorkspaceMaxRateLimitEntries,
		"ws_max_sessions", Global.WorkspaceMaxSessions,
		"ws_max_event_subs", Global.WorkspaceMaxEventSubs,
		"ws_max_callbacks", Global.WorkspaceMaxCallbacks,
		"ws_max_event_handlers", Global.WorkspaceMaxEventHandlers,
		"workspace_mode", Global.WorkspaceMode,
		"workspace_id", Global.WorkspaceID,
		"enforce_tls_verify", Global.EnforceTLSVerify,
	)
}

// getEnvString reads an environment variable as a string, or returns the default.
func getEnvString(key string, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return strings.TrimSpace(val)
	}
	return defaultVal
}

// getEnvInt reads an environment variable as an integer, or returns the default.
func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
		slog.Warn("invalid int env var, using default", "key", key, "value", val, "default", defaultVal)
	}
	return defaultVal
}

// getEnvInt64 reads an environment variable as an int64, or returns the default.
func getEnvInt64(key string, defaultVal int64) int64 {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
		slog.Warn("invalid int64 env var, using default", "key", key, "value", val, "default", defaultVal)
	}
	return defaultVal
}

// getEnvBool reads an environment variable as a boolean, or returns the default.
// Accepted true values: "true", "1", "yes". Everything else is false.
func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		default:
			slog.Warn("invalid bool env var, using default", "key", key, "value", val, "default", defaultVal)
		}
	}
	return defaultVal
}

// getEnvStringSlice reads a comma-separated environment variable, or returns the default.
func getEnvStringSlice(key string, defaultVal []string) []string {
	if val := os.Getenv(key); val != "" {
		var result []string
		for _, s := range strings.Split(val, ",") {
			if s = strings.TrimSpace(s); s != "" {
				result = append(result, s)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultVal
}
