package cache

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrivacyGuard_DefaultLevel(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *PrivacyConfig
		wantLvl PrivacyLevel
	}{
		{
			name:    "nil config defaults to full",
			cfg:     nil,
			wantLvl: PrivacyFull,
		},
		{
			name:    "empty default level defaults to full",
			cfg:     &PrivacyConfig{},
			wantLvl: PrivacyFull,
		},
		{
			name:    "explicit full",
			cfg:     &PrivacyConfig{DefaultLevel: PrivacyFull},
			wantLvl: PrivacyFull,
		},
		{
			name:    "explicit metrics",
			cfg:     &PrivacyConfig{DefaultLevel: PrivacyMetrics},
			wantLvl: PrivacyMetrics,
		},
		{
			name:    "explicit none",
			cfg:     &PrivacyConfig{DefaultLevel: PrivacyNone},
			wantLvl: PrivacyNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pg := NewPrivacyGuard(tt.cfg)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			got := pg.ResolveLevel(r)
			assert.Equal(t, tt.wantLvl, got)
		})
	}
}

func TestPrivacyGuard_HeaderOverride(t *testing.T) {
	tests := []struct {
		name        string
		defaultLvl  PrivacyLevel
		headerVal   string
		headerName  string
		wantLvl     PrivacyLevel
	}{
		{
			name:       "header more restrictive wins",
			defaultLvl: PrivacyFull,
			headerVal:  "none",
			wantLvl:    PrivacyNone,
		},
		{
			name:       "header less restrictive ignored",
			defaultLvl: PrivacyNone,
			headerVal:  "full",
			wantLvl:    PrivacyNone,
		},
		{
			name:       "metrics overrides full",
			defaultLvl: PrivacyFull,
			headerVal:  "metrics",
			wantLvl:    PrivacyMetrics,
		},
		{
			name:       "invalid header value ignored",
			defaultLvl: PrivacyFull,
			headerVal:  "invalid-level",
			wantLvl:    PrivacyFull,
		},
		{
			name:       "empty header value ignored",
			defaultLvl: PrivacyMetrics,
			headerVal:  "",
			wantLvl:    PrivacyMetrics,
		},
		{
			name:       "custom header name",
			defaultLvl: PrivacyFull,
			headerVal:  "none",
			headerName: "X-Custom-Privacy",
			wantLvl:    PrivacyNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headerName := tt.headerName
			if headerName == "" {
				headerName = "X-SB-Cache-Privacy"
			}
			pg := NewPrivacyGuard(&PrivacyConfig{
				DefaultLevel:   tt.defaultLvl,
				HeaderOverride: tt.headerName,
			})
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.headerVal != "" {
				r.Header.Set(headerName, tt.headerVal)
			}
			got := pg.ResolveLevel(r)
			assert.Equal(t, tt.wantLvl, got)
		})
	}
}

func TestPrivacyGuard_PolicyOverride(t *testing.T) {
	tests := []struct {
		name       string
		defaultLvl PrivacyLevel
		policyLvl  PrivacyLevel
		wantLvl    PrivacyLevel
	}{
		{
			name:       "policy more restrictive wins",
			defaultLvl: PrivacyFull,
			policyLvl:  PrivacyNone,
			wantLvl:    PrivacyNone,
		},
		{
			name:       "policy less restrictive ignored",
			defaultLvl: PrivacyNone,
			policyLvl:  PrivacyFull,
			wantLvl:    PrivacyNone,
		},
		{
			name:       "policy metrics overrides full",
			defaultLvl: PrivacyFull,
			policyLvl:  PrivacyMetrics,
			wantLvl:    PrivacyMetrics,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pg := NewPrivacyGuard(&PrivacyConfig{
				DefaultLevel: tt.defaultLvl,
				PolicyLevel:  tt.policyLvl,
			})
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			got := pg.ResolveLevel(r)
			assert.Equal(t, tt.wantLvl, got)
		})
	}
}

func TestPrivacyGuard_Precedence(t *testing.T) {
	// Full precedence chain: policy > header > config.
	// Default: full, Header: metrics, Policy: none. Result should be "none".
	pg := NewPrivacyGuard(&PrivacyConfig{
		DefaultLevel: PrivacyFull,
		PolicyLevel:  PrivacyNone,
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-SB-Cache-Privacy", "metrics")
	got := pg.ResolveLevel(r)
	assert.Equal(t, PrivacyNone, got, "policy should be the most restrictive and win")

	// Default: none, Header: full, Policy: full.
	// Default is already most restrictive, result should remain "none".
	pg2 := NewPrivacyGuard(&PrivacyConfig{
		DefaultLevel: PrivacyNone,
		PolicyLevel:  PrivacyFull,
	})
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-SB-Cache-Privacy", "full")
	got2 := pg2.ResolveLevel(r2)
	assert.Equal(t, PrivacyNone, got2, "default none should not be relaxed by header or policy")
}

func TestAllowCache(t *testing.T) {
	tests := []struct {
		level PrivacyLevel
		want  bool
	}{
		{PrivacyFull, true},
		{PrivacyMetrics, true},
		{PrivacyNone, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			assert.Equal(t, tt.want, AllowCache(tt.level))
		})
	}
}

func TestAllowMetrics(t *testing.T) {
	tests := []struct {
		level PrivacyLevel
		want  bool
	}{
		{PrivacyFull, true},
		{PrivacyMetrics, true},
		{PrivacyNone, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			assert.Equal(t, tt.want, AllowMetrics(tt.level))
		})
	}
}

func TestAllowContent(t *testing.T) {
	tests := []struct {
		level PrivacyLevel
		want  bool
	}{
		{PrivacyFull, true},
		{PrivacyMetrics, false},
		{PrivacyNone, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			assert.Equal(t, tt.want, AllowContent(tt.level))
		})
	}
}

func TestMoreRestrictive(t *testing.T) {
	tests := []struct {
		a, b PrivacyLevel
		want PrivacyLevel
	}{
		{PrivacyFull, PrivacyFull, PrivacyFull},
		{PrivacyFull, PrivacyMetrics, PrivacyMetrics},
		{PrivacyFull, PrivacyNone, PrivacyNone},
		{PrivacyMetrics, PrivacyFull, PrivacyMetrics},
		{PrivacyMetrics, PrivacyMetrics, PrivacyMetrics},
		{PrivacyMetrics, PrivacyNone, PrivacyNone},
		{PrivacyNone, PrivacyFull, PrivacyNone},
		{PrivacyNone, PrivacyMetrics, PrivacyNone},
		{PrivacyNone, PrivacyNone, PrivacyNone},
	}
	for _, tt := range tests {
		t.Run(string(tt.a)+"_vs_"+string(tt.b), func(t *testing.T) {
			got := moreRestrictive(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPrivacyGuard_NilRequest(t *testing.T) {
	pg := NewPrivacyGuard(&PrivacyConfig{DefaultLevel: PrivacyMetrics})
	// nil request should not panic and should return default level.
	got := pg.ResolveLevel(nil)
	assert.Equal(t, PrivacyMetrics, got)
}

func TestPrivacyGuard_NoConfig(t *testing.T) {
	pg := NewPrivacyGuard(nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	got := pg.ResolveLevel(r)
	assert.Equal(t, PrivacyFull, got, "nil config should default to full privacy level")
}
