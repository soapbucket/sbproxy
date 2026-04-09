package config

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}
	if nonce1 == "" {
		t.Error("GenerateNonce() returned empty nonce")
	}

	// Generate another nonce and verify they're different
	nonce2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}
	if nonce1 == nonce2 {
		t.Error("GenerateNonce() returned duplicate nonces")
	}

	// Verify nonce is base64 encoded (should be valid base64)
	if len(nonce1) < 16 {
		t.Error("Nonce should be at least 16 characters")
	}
}

func TestCalculateHash(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantLen int // Expected minimum length of hash
	}{
		{"simple script", "console.log('test');", 40},
		{"empty string", "", 0},
		{"long script", strings.Repeat("console.log('test');", 100), 40},
		{"special characters", "alert('XSS'); <script>", 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := CalculateHash(tt.content)
			if tt.content == "" {
				if hash != "" {
					t.Errorf("CalculateHash() for empty string should return empty, got %q", hash)
				}
				return
			}
			if len(hash) < tt.wantLen {
				t.Errorf("CalculateHash() length = %d, want at least %d", len(hash), tt.wantLen)
			}
			// Verify same content produces same hash
			hash2 := CalculateHash(tt.content)
			if hash != hash2 {
				t.Errorf("CalculateHash() should be deterministic, got different hashes")
			}
		})
	}
}

func TestBuildCSPPolicy(t *testing.T) {
	tests := []struct {
		name      string
		directives *CSPDirectives
		nonce     string
		hashes    []string
		want      string
		wantContains []string
	}{
		{
			name: "basic directives",
			directives: &CSPDirectives{
				DefaultSrc: []string{"'self'"},
				ScriptSrc:  []string{"'self'"},
				StyleSrc:   []string{"'self'"},
			},
			wantContains: []string{"default-src 'self'", "script-src 'self'", "style-src 'self'"},
		},
		{
			name: "with nonce",
			directives: &CSPDirectives{
				ScriptSrc: []string{"'self'"},
			},
			nonce: "test-nonce-123",
			wantContains: []string{"script-src 'self'", "'nonce-test-nonce-123'"},
		},
		{
			name: "with hash",
			directives: &CSPDirectives{
				ScriptSrc: []string{"'self'"},
			},
			hashes: []string{"abc123"},
			wantContains: []string{"script-src 'self'", "'sha256-abc123'"},
		},
		{
			name: "with nonce and hash",
			directives: &CSPDirectives{
				ScriptSrc: []string{"'self'"},
			},
			nonce: "test-nonce",
			hashes: []string{"hash123"},
			wantContains: []string{"'nonce-test-nonce'", "'sha256-hash123'"},
		},
		{
			name: "upgrade insecure requests",
			directives: &CSPDirectives{
				DefaultSrc: []string{"'self'"},
				UpgradeInsecureRequests: true,
			},
			wantContains: []string{"upgrade-insecure-requests"},
		},
		{
			name: "all directives",
			directives: &CSPDirectives{
				DefaultSrc:     []string{"'self'"},
				ScriptSrc:      []string{"'self'"},
				StyleSrc:       []string{"'self'"},
				ImgSrc:         []string{"'self'", "data:"},
				FontSrc:        []string{"'self'"},
				ConnectSrc:     []string{"'self'"},
				FrameSrc:       []string{"'none'"},
				ObjectSrc:      []string{"'none'"},
				MediaSrc:       []string{"'self'"},
				FrameAncestors: []string{"'none'"},
				BaseURI:        []string{"'self'"},
				FormAction:     []string{"'self'"},
			},
			wantContains: []string{
				"default-src 'self'",
				"script-src 'self'",
				"style-src 'self'",
				"img-src 'self' data:",
				"font-src 'self'",
				"connect-src 'self'",
				"frame-src 'none'",
				"object-src 'none'",
				"media-src 'self'",
				"frame-ancestors 'none'",
				"base-uri 'self'",
				"form-action 'self'",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildCSPPolicy(tt.directives, tt.nonce, tt.hashes)
			
			if tt.want != "" && got != tt.want {
				t.Errorf("BuildCSPPolicy() = %q, want %q", got, tt.want)
			}

			for _, wantContains := range tt.wantContains {
				if !strings.Contains(got, wantContains) {
					t.Errorf("BuildCSPPolicy() = %q, should contain %q", got, wantContains)
				}
			}
		})
	}
}

func TestBuildCSPPolicy_NilDirectives(t *testing.T) {
	got := BuildCSPPolicy(nil, "", nil)
	if got != "" {
		t.Errorf("BuildCSPPolicy(nil) = %q, want empty string", got)
	}
}

func TestCSPConfig_GetCSPForRoute(t *testing.T) {
	csp := &CSPConfig{
		Enabled: true,
		Directives: &CSPDirectives{
			DefaultSrc: []string{"'self'"},
		},
		DynamicRoutes: map[string]*CSPConfig{
			"/admin": {
				Enabled: true,
				Directives: &CSPDirectives{
					DefaultSrc: []string{"'self'"},
					ScriptSrc:  []string{"'self'"},
				},
			},
			"/api": {
				Enabled: true,
				Directives: &CSPDirectives{
					DefaultSrc: []string{"'self'"},
					ConnectSrc: []string{"'self'", "https://api.example.com"},
				},
			},
		},
	}

	tests := []struct {
		name     string
		path     string
		wantPath string // Expected matched route path
	}{
		{"exact match /admin", "/admin", "/admin"},
		{"prefix match /admin/users", "/admin/users", "/admin"},
		{"exact match /api", "/api", "/api"},
		{"prefix match /api/v1", "/api/v1", "/api"},
		{"no match", "/public", ""},
		{"longest match wins", "/api/admin", "/api"}, // /api matches before /admin
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csp.GetCSPForRoute(tt.path)
			if tt.wantPath == "" {
				// Should return default CSP
				if got != csp {
					t.Errorf("GetCSPForRoute() = %v, want default CSP", got)
				}
			} else {
				// Should return route-specific CSP
				if got == csp {
					t.Errorf("GetCSPForRoute() returned default CSP, want route-specific")
				}
			}
		})
	}
}

func TestCSPConfig_BuildPolicyString(t *testing.T) {
	tests := []struct {
		name     string
		csp      *CSPConfig
		path     string
		nonce    string
		wantContains []string
	}{
		{
			name: "simple policy string",
			csp: &CSPConfig{
				Enabled: true,
				Policy:  "default-src 'self'; script-src 'self'",
			},
			path: "/",
			wantContains: []string{"default-src 'self'", "script-src 'self'"},
		},
		{
			name: "structured directives",
			csp: &CSPConfig{
				Enabled: true,
				Directives: &CSPDirectives{
					DefaultSrc: []string{"'self'"},
					ScriptSrc:  []string{"'self'"},
				},
			},
			path: "/",
			wantContains: []string{"default-src 'self'", "script-src 'self'"},
		},
		{
			name: "with nonce",
			csp: &CSPConfig{
				Enabled:    true,
				EnableNonce: true,
				Directives: &CSPDirectives{
					ScriptSrc: []string{"'self'"},
				},
			},
			path:  "/",
			nonce: "test-nonce",
			wantContains: []string{"'nonce-test-nonce'"},
		},
		{
			name: "route-specific policy",
			csp: &CSPConfig{
				Enabled: true,
				Directives: &CSPDirectives{
					DefaultSrc: []string{"'self'"},
				},
				DynamicRoutes: map[string]*CSPConfig{
					"/admin": {
						Enabled: true,
						Directives: &CSPDirectives{
							DefaultSrc: []string{"'self'"},
							ScriptSrc:  []string{"'self'"},
						},
					},
				},
			},
			path: "/admin",
			wantContains: []string{"script-src 'self'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.path, nil)
			got := tt.csp.BuildPolicyString(r, tt.nonce, nil)

			for _, wantContains := range tt.wantContains {
				if !strings.Contains(got, wantContains) {
					t.Errorf("BuildPolicyString() = %q, should contain %q", got, wantContains)
				}
			}
		})
	}
}

func TestWithCSPNonce(t *testing.T) {
	ctx := context.Background()
	nonce := "test-nonce-123"

	ctxWithNonce := WithCSPNonce(ctx, nonce)
	retrievedNonce, ok := GetCSPNonce(ctxWithNonce)

	if !ok {
		t.Error("GetCSPNonce() should return true when nonce is set")
	}
	if retrievedNonce != nonce {
		t.Errorf("GetCSPNonce() = %q, want %q", retrievedNonce, nonce)
	}
}

func TestGetCSPNonce_NotSet(t *testing.T) {
	ctx := context.Background()
	_, ok := GetCSPNonce(ctx)

	if ok {
		t.Error("GetCSPNonce() should return false when nonce is not set")
	}
}

func TestInjectNonceIntoPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		nonce    string
		wantContains []string
	}{
		{
			name:   "script-src with nonce",
			policy: "script-src 'self'",
			nonce:  "test123",
			wantContains: []string{"script-src 'self'", "'nonce-test123'"},
		},
		{
			name:   "style-src with nonce",
			policy: "style-src 'self'",
			nonce:  "test123",
			wantContains: []string{"style-src 'self'", "'nonce-test123'"},
		},
		{
			name:   "both script and style",
			policy: "script-src 'self'; style-src 'self'",
			nonce:  "test123",
			wantContains: []string{"script-src 'self'", "style-src 'self'", "'nonce-test123'"},
		},
		{
			name:   "no script or style",
			policy: "default-src 'self'",
			nonce:  "test123",
			wantContains: []string{"default-src 'self'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := injectNonceIntoPolicy(tt.policy, tt.nonce)

			for _, wantContains := range tt.wantContains {
				if !strings.Contains(got, wantContains) {
					t.Errorf("injectNonceIntoPolicy() = %q, should contain %q", got, wantContains)
				}
			}

			// Verify nonce appears correct number of times (once per script-src/style-src)
			nonceCount := strings.Count(got, "'nonce-"+tt.nonce+"'")
			expectedCount := 0
			if strings.Contains(tt.policy, "script-src") {
				expectedCount++
			}
			if strings.Contains(tt.policy, "style-src") {
				expectedCount++
			}
			if nonceCount != expectedCount {
				t.Errorf("injectNonceIntoPolicy() nonce count = %d, want %d", nonceCount, expectedCount)
			}
		})
	}
}

