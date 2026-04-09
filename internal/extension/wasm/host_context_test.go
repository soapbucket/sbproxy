package wasm

import (
	"testing"
)

func TestRequestContext_Variables(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetVariable("env")
	if ok {
		t.Error("expected false for non-existent variable")
	}

	rc.mu.Lock()
	rc.Variables["env"] = "production"
	rc.Variables["region"] = "us-east-1"
	rc.mu.Unlock()

	val, ok := rc.GetVariable("env")
	if !ok || val != "production" {
		t.Errorf("expected env=%q, got %q (ok=%v)", "production", val, ok)
	}

	val, ok = rc.GetVariable("region")
	if !ok || val != "us-east-1" {
		t.Errorf("expected region=%q, got %q (ok=%v)", "us-east-1", val, ok)
	}

	_, ok = rc.GetVariable("missing")
	if ok {
		t.Error("expected false for missing variable")
	}
}

func TestRequestContext_ClientIP(t *testing.T) {
	rc := NewRequestContext()

	if ip := rc.GetClientIP(); ip != "" {
		t.Errorf("expected empty client IP, got %q", ip)
	}

	rc.mu.Lock()
	rc.ClientIP = "192.168.1.1"
	rc.mu.Unlock()

	if ip := rc.GetClientIP(); ip != "192.168.1.1" {
		t.Errorf("expected %q, got %q", "192.168.1.1", ip)
	}
}

func TestRequestContext_GeoCountry(t *testing.T) {
	rc := NewRequestContext()

	if c := rc.GetGeoCountry(); c != "" {
		t.Errorf("expected empty geo country, got %q", c)
	}

	rc.mu.Lock()
	rc.GeoCountry = "US"
	rc.mu.Unlock()

	if c := rc.GetGeoCountry(); c != "US" {
		t.Errorf("expected %q, got %q", "US", c)
	}
}

func TestRequestContext_SessionID(t *testing.T) {
	rc := NewRequestContext()

	if s := rc.GetSessionID(); s != "" {
		t.Errorf("expected empty session ID, got %q", s)
	}

	rc.mu.Lock()
	rc.SessionID = "sess-abc-123"
	rc.mu.Unlock()

	if s := rc.GetSessionID(); s != "sess-abc-123" {
		t.Errorf("expected %q, got %q", "sess-abc-123", s)
	}
}

func TestRequestContext_OriginSecret(t *testing.T) {
	rc := NewRequestContext()

	if _, ok := rc.GetOriginSecret("API_TOKEN"); ok {
		t.Error("expected missing origin secret to return false")
	}

	rc.mu.Lock()
	rc.OriginSecrets = map[string]string{
		"API_TOKEN": "secret-value",
	}
	rc.mu.Unlock()

	val, ok := rc.GetOriginSecret("API_TOKEN")
	if !ok || val != "secret-value" {
		t.Errorf("expected API_TOKEN=secret-value, got %q (ok=%v)", val, ok)
	}
}
