package manager

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// TestValidateSettings tests the settings validation function
func TestValidateSettings(t *testing.T) {
	tests := []struct {
		name     string
		settings GlobalSettings
		wantErr  error
	}{
		{
			name: "valid settings",
			settings: GlobalSettings{
				CacherSettings: map[CacheLevel]cacher.Settings{
					L1Cache: {Driver: "memory"},
				},
				CompressionLevel: 5,
			},
			wantErr: nil,
		},
		{
			name: "missing cacher settings",
			settings: GlobalSettings{
				CacherSettings:   map[CacheLevel]cacher.Settings{},
				CompressionLevel: 5,
			},
			wantErr: ErrInvalidSettings,
		},
		{
			name: "compression level too low",
			settings: GlobalSettings{
				CacherSettings: map[CacheLevel]cacher.Settings{
					L1Cache: {Driver: "memory"},
				},
				CompressionLevel: -1,
			},
			wantErr: ErrInvalidCompressionLevel,
		},
		{
			name: "compression level too high",
			settings: GlobalSettings{
				CacherSettings: map[CacheLevel]cacher.Settings{
					L1Cache: {Driver: "memory"},
				},
				CompressionLevel: 10,
			},
			wantErr: ErrInvalidCompressionLevel,
		},
		{
			name: "compression level at minimum",
			settings: GlobalSettings{
				CacherSettings: map[CacheLevel]cacher.Settings{
					L1Cache: {Driver: "memory"},
				},
				CompressionLevel: 0,
			},
			wantErr: nil,
		},
		{
			name: "compression level at maximum",
			settings: GlobalSettings{
				CacherSettings: map[CacheLevel]cacher.Settings{
					L1Cache: {Driver: "memory"},
				},
				CompressionLevel: 9,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSettings(tt.settings)
			if err != tt.wantErr {
				t.Errorf("validateSettings() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestCacheLevel tests the CacheLevel constants
func TestCacheLevel(t *testing.T) {
	tests := []struct {
		name  string
		level CacheLevel
		want  int
	}{
		{
			name:  "L1Cache",
			level: L1Cache,
			want:  0,
		},
		{
			name:  "L2Cache",
			level: L2Cache,
			want:  1,
		},
		{
			name:  "L3Cache",
			level: L3Cache,
			want:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.level) != tt.want {
				t.Errorf("CacheLevel %s = %d, want %d", tt.name, tt.level, tt.want)
			}
		})
	}
}

// TestGlobalSettings tests the GlobalSettings struct
func TestGlobalSettings(t *testing.T) {
	settings := GlobalSettings{
		OriginLoaderSettings: OriginLoaderSettings{
			MaxOriginForwardDepth: 10,
			OriginCacheTTL:        5 * time.Minute,
			HostnameFallback:      true,
		},
		CookieSettings: CookieSettings{
			SessionCookieName: "session",
			SessionMaxAge:     3600,
			StickyCookieName:  "sticky",
		},
		HTTP3Settings: HTTP3Settings{
			EnableHTTP3:   true,
			HTTP3BindPort: 443,
		},
		DebugSettings: DebugSettings{
			Debug:          true,
			DisplayHeaders: true,
		},
		CompressionLevel:  5,
		L2CacheTimeout:    10 * time.Minute,
		MaxRecursionDepth: 5,
	}

	// Test OriginLoaderSettings
	if settings.OriginLoaderSettings.MaxOriginForwardDepth != 10 {
		t.Errorf("MaxOriginForwardDepth = %d, want 10", settings.OriginLoaderSettings.MaxOriginForwardDepth)
	}
	if settings.OriginLoaderSettings.OriginCacheTTL != 5*time.Minute {
		t.Errorf("OriginCacheTTL = %v, want 5m", settings.OriginLoaderSettings.OriginCacheTTL)
	}
	if !settings.OriginLoaderSettings.HostnameFallback {
		t.Error("HostnameFallback should be true")
	}

	// Test CookieSettings
	if settings.CookieSettings.SessionCookieName != "session" {
		t.Errorf("SessionCookieName = %s, want session", settings.CookieSettings.SessionCookieName)
	}
	if settings.CookieSettings.SessionMaxAge != 3600 {
		t.Errorf("SessionMaxAge = %d, want 3600", settings.CookieSettings.SessionMaxAge)
	}

	// Test HTTP3Settings
	if !settings.HTTP3Settings.EnableHTTP3 {
		t.Error("EnableHTTP3 should be true")
	}
	if settings.HTTP3Settings.HTTP3BindPort != 443 {
		t.Errorf("HTTP3BindPort = %d, want 443", settings.HTTP3Settings.HTTP3BindPort)
	}

	// Test DebugSettings
	if !settings.DebugSettings.Debug {
		t.Error("Debug should be true")
	}
	if !settings.DebugSettings.DisplayHeaders {
		t.Error("DisplayHeaders should be true")
	}

	// Test other settings
	if settings.CompressionLevel != 5 {
		t.Errorf("CompressionLevel = %d, want 5", settings.CompressionLevel)
	}
	if settings.L2CacheTimeout != 10*time.Minute {
		t.Errorf("L2CacheTimeout = %v, want 10m", settings.L2CacheTimeout)
	}
	if settings.MaxRecursionDepth != 5 {
		t.Errorf("MaxRecursionDepth = %d, want 5", settings.MaxRecursionDepth)
	}
}

// TestWorkerPoolStats tests the WorkerPoolStats struct
func TestWorkerPoolStats(t *testing.T) {
	stats := WorkerPoolStats{
		Name:           "test-pool",
		MaxWorkers:     10,
		ActiveWorkers:  5,
		TotalSubmitted: 100,
		TotalCompleted: 95,
		TotalFailed:    2,
	}

	if stats.Name != "test-pool" {
		t.Errorf("Name = %s, want test-pool", stats.Name)
	}
	if stats.MaxWorkers != 10 {
		t.Errorf("MaxWorkers = %d, want 10", stats.MaxWorkers)
	}
	if stats.ActiveWorkers != 5 {
		t.Errorf("ActiveWorkers = %d, want 5", stats.ActiveWorkers)
	}
	if stats.TotalSubmitted != 100 {
		t.Errorf("TotalSubmitted = %d, want 100", stats.TotalSubmitted)
	}
	if stats.TotalCompleted != 95 {
		t.Errorf("TotalCompleted = %d, want 95", stats.TotalCompleted)
	}
	if stats.TotalFailed != 2 {
		t.Errorf("TotalFailed = %d, want 2", stats.TotalFailed)
	}
}

// TestManagerContext tests the context key for manager
func TestManagerContext(t *testing.T) {
	ctx := context.Background()

	// Test GetManager with no manager in context
	m := GetManager(ctx)
	if m != nil {
		t.Error("expected nil manager from empty context")
	}
}

// TestErrors tests the error variables
func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrInvalidSessionConfiguration",
			err:  ErrInvalidSessionConfiguration,
			want: "manager:invalid session configuration",
		},
		{
			name: "ErrInvalidCompressionLevel",
			err:  ErrInvalidCompressionLevel,
			want: "manager:invalid compression level",
		},
		{
			name: "ErrInvalidSettings",
			err:  ErrInvalidSettings,
			want: "manager:invalid settings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.want {
				t.Errorf("error message = %s, want %s", tt.err.Error(), tt.want)
			}
		})
	}
}

// BenchmarkValidateSettings benchmarks settings validation
func BenchmarkValidateSettings(b *testing.B) {
	b.ReportAllocs()
	settings := GlobalSettings{
		CacherSettings: map[CacheLevel]cacher.Settings{
			L1Cache: {Driver: "memory"},
			L2Cache: {Driver: "memory"},
		},
		CompressionLevel: 5,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validateSettings(settings)
	}
}
