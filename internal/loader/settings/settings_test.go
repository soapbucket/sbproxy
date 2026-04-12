package settings

import (
	"os"
	"testing"
)

func TestSettingsDefaults(t *testing.T) {
	// Reset environment
	os.Clearenv()

	// Re-initialize globals (in practice, this happens at startup)
	s := ProcessSettings{
		MaxCoalesceBodyBytes:         getEnvInt64("SB_MAX_COALESCE_BODY", 10*1024*1024),
		MaxJWKSBodyBytes:             getEnvInt64("SB_MAX_JWKS_BODY", 1*1024*1024),
		MaxRetryBodyBytes:            getEnvInt64("SB_MAX_RETRY_BODY", 32*1024*1024),
		MaxCallbackBodyBytes:         getEnvInt64("SB_MAX_CALLBACK_BODY", 10*1024*1024),
		TrustedProxyCIDRs:            getEnvStringSlice("SB_TRUSTED_PROXIES", []string{}),
		WorkspaceMaxCachedConfigs:    getEnvInt("SB_WS_MAX_CONFIGS", 1000),
		WorkspaceMaxRateLimitEntries: getEnvInt("SB_WS_MAX_RATE_ENTRIES", 10000),
		WorkspaceMaxSessions:         getEnvInt("SB_WS_MAX_SESSIONS", 10000),
		WorkspaceMaxEventSubs:        getEnvInt("SB_WS_MAX_EVENT_SUBS", 100),
		WorkspaceMaxCallbacks:        getEnvInt("SB_WS_MAX_CALLBACKS", 50),
		WorkspaceMaxEventHandlers:    getEnvInt("SB_WS_MAX_EVENT_HANDLERS", 32),
	}

	// Verify defaults
	if s.MaxCoalesceBodyBytes != 10*1024*1024 {
		t.Errorf("MaxCoalesceBodyBytes: got %d, want 10485760", s.MaxCoalesceBodyBytes)
	}
	if s.MaxJWKSBodyBytes != 1*1024*1024 {
		t.Errorf("MaxJWKSBodyBytes: got %d, want 1048576", s.MaxJWKSBodyBytes)
	}
	if s.MaxRetryBodyBytes != 32*1024*1024 {
		t.Errorf("MaxRetryBodyBytes: got %d, want 33554432", s.MaxRetryBodyBytes)
	}
	if s.MaxCallbackBodyBytes != 10*1024*1024 {
		t.Errorf("MaxCallbackBodyBytes: got %d, want 10485760", s.MaxCallbackBodyBytes)
	}
	if len(s.TrustedProxyCIDRs) != 0 {
		t.Errorf("TrustedProxyCIDRs: got %d, want 0", len(s.TrustedProxyCIDRs))
	}
	if s.WorkspaceMaxCachedConfigs != 1000 {
		t.Errorf("WorkspaceMaxCachedConfigs: got %d, want 1000", s.WorkspaceMaxCachedConfigs)
	}
	if s.WorkspaceMaxRateLimitEntries != 10000 {
		t.Errorf("WorkspaceMaxRateLimitEntries: got %d, want 10000", s.WorkspaceMaxRateLimitEntries)
	}
	if s.WorkspaceMaxSessions != 10000 {
		t.Errorf("WorkspaceMaxSessions: got %d, want 10000", s.WorkspaceMaxSessions)
	}
	if s.WorkspaceMaxEventSubs != 100 {
		t.Errorf("WorkspaceMaxEventSubs: got %d, want 100", s.WorkspaceMaxEventSubs)
	}
	if s.WorkspaceMaxCallbacks != 50 {
		t.Errorf("WorkspaceMaxCallbacks: got %d, want 50", s.WorkspaceMaxCallbacks)
	}
	if s.WorkspaceMaxEventHandlers != 32 {
		t.Errorf("WorkspaceMaxEventHandlers: got %d, want 32", s.WorkspaceMaxEventHandlers)
	}
}

func TestSettingsEnvOverride(t *testing.T) {
	// Set environment variables
	os.Setenv("SB_MAX_COALESCE_BODY", "5242880")
	defer os.Unsetenv("SB_MAX_COALESCE_BODY")

	os.Setenv("SB_TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.0/12")
	defer os.Unsetenv("SB_TRUSTED_PROXIES")

	os.Setenv("SB_WS_MAX_CONFIGS", "500")
	defer os.Unsetenv("SB_WS_MAX_CONFIGS")

	// Read with overrides
	s := ProcessSettings{
		MaxCoalesceBodyBytes:      getEnvInt64("SB_MAX_COALESCE_BODY", 10*1024*1024),
		TrustedProxyCIDRs:         getEnvStringSlice("SB_TRUSTED_PROXIES", []string{}),
		WorkspaceMaxCachedConfigs: getEnvInt("SB_WS_MAX_CONFIGS", 1000),
	}

	if s.MaxCoalesceBodyBytes != 5242880 {
		t.Errorf("MaxCoalesceBodyBytes: got %d, want 5242880", s.MaxCoalesceBodyBytes)
	}
	if len(s.TrustedProxyCIDRs) != 2 {
		t.Errorf("TrustedProxyCIDRs: got %d items, want 2", len(s.TrustedProxyCIDRs))
	}
	if s.TrustedProxyCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("TrustedProxyCIDRs[0]: got %s, want 10.0.0.0/8", s.TrustedProxyCIDRs[0])
	}
	if s.WorkspaceMaxCachedConfigs != 500 {
		t.Errorf("WorkspaceMaxCachedConfigs: got %d, want 500", s.WorkspaceMaxCachedConfigs)
	}
}

func TestSettingsInvalidEnv(t *testing.T) {
	// Set invalid values
	os.Setenv("SB_MAX_COALESCE_BODY", "not-a-number")
	defer os.Unsetenv("SB_MAX_COALESCE_BODY")

	os.Setenv("SB_WS_MAX_CONFIGS", "invalid")
	defer os.Unsetenv("SB_WS_MAX_CONFIGS")

	// Should fall back to defaults
	s := ProcessSettings{
		MaxCoalesceBodyBytes:      getEnvInt64("SB_MAX_COALESCE_BODY", 10*1024*1024),
		WorkspaceMaxCachedConfigs: getEnvInt("SB_WS_MAX_CONFIGS", 1000),
	}

	if s.MaxCoalesceBodyBytes != 10*1024*1024 {
		t.Errorf("MaxCoalesceBodyBytes: got %d, want default 10485760", s.MaxCoalesceBodyBytes)
	}
	if s.WorkspaceMaxCachedConfigs != 1000 {
		t.Errorf("WorkspaceMaxCachedConfigs: got %d, want default 1000", s.WorkspaceMaxCachedConfigs)
	}
}
