package ipfilter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNew_ValidConfig verifies that valid configs create an enforcer.
func TestNew_ValidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "whitelist only",
			json: `{"type":"ip_filtering","whitelist":["192.168.1.0/24"]}`,
		},
		{
			name: "blacklist only",
			json: `{"type":"ip_filtering","blacklist":["10.0.0.0/8"]}`,
		},
		{
			name: "single IP",
			json: `{"type":"ip_filtering","whitelist":["192.168.1.1"]}`,
		},
		{
			name: "IPv6 CIDR",
			json: `{"type":"ip_filtering","whitelist":["::1"]}`,
		},
		{
			name: "empty config",
			json: `{"type":"ip_filtering"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enforcer, err := New(json.RawMessage(tc.json))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if enforcer == nil {
				t.Fatal("expected non-nil enforcer")
			}
		})
	}
}

// TestNew_InvalidJSON verifies that invalid JSON returns an error.
func TestNew_InvalidJSON(t *testing.T) {
	_, err := New(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestType verifies the Type() method returns the correct string.
func TestType(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"ip_filtering"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip := enforcer.(*ipFilterPolicy)
	if ip.Type() != "ip_filtering" {
		t.Errorf("expected type 'ip_filtering', got %q", ip.Type())
	}
}

// TestEnforce_Disabled verifies that disabled policy passes through.
func TestEnforce_Disabled(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"ip_filtering","disabled":true,"blacklist":["0.0.0.0/0"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called when policy is disabled")
	}
}

// TestEnforce_Whitelist_Allowed verifies whitelisted IP passes.
func TestEnforce_Whitelist_Allowed(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"ip_filtering","whitelist":["192.168.1.0/24"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called for whitelisted IP")
	}
}

// TestEnforce_Whitelist_Blocked verifies non-whitelisted IP is blocked.
func TestEnforce_Whitelist_Blocked(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"ip_filtering","whitelist":["192.168.1.0/24"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("expected next handler NOT to be called for non-whitelisted IP")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// TestEnforce_Blacklist_Blocked verifies blacklisted IP is blocked.
func TestEnforce_Blacklist_Blocked(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"ip_filtering","blacklist":["10.0.0.0/8"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("expected next handler NOT to be called for blacklisted IP")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// TestEnforce_Blacklist_Allowed verifies non-blacklisted IP passes.
func TestEnforce_Blacklist_Allowed(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"ip_filtering","blacklist":["10.0.0.0/8"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called for non-blacklisted IP")
	}
}

// TestGetClientIPWithTrustedProxies verifies IP extraction logic.
func TestGetClientIPWithTrustedProxies(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		expected   string
	}{
		{
			name:       "direct connection",
			remoteAddr: "192.168.1.1:1234",
			expected:   "192.168.1.1",
		},
		{
			name:       "no port in remote addr",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
		{
			name:       "empty remote addr",
			remoteAddr: "",
			expected:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}

			got := getClientIPWithTrustedProxies(req, nil)
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

// TestNew_InvalidTemporaryBanDuration verifies invalid duration returns an error.
func TestNew_InvalidTemporaryBanDuration(t *testing.T) {
	_, err := New(json.RawMessage(`{"type":"ip_filtering","temporary_bans":{"192.168.1.1":"invalid-duration"}}`))
	if err == nil {
		t.Fatal("expected error for invalid temporary ban duration")
	}
}
