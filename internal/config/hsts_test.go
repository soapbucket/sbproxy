package config

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

func TestHSTS_BasicHeader(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	req := &http.Request{
		TLS: &tls.ConnectionState{},
	}

	cfg := &HSTSConfig{
		Enabled: true,
		MaxAge:  31536000,
	}

	applyHSTSHeader(resp, req, cfg)

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatal("expected HSTS header")
	}

	if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("expected max-age=31536000, got %s", hsts)
	}
}

func TestHSTS_WithSubDomainsAndPreload(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	req := &http.Request{
		TLS: &tls.ConnectionState{},
	}

	cfg := &HSTSConfig{
		Enabled:           true,
		MaxAge:            63072000,
		IncludeSubdomains: true,
		Preload:           true,
	}

	applyHSTSHeader(resp, req, cfg)

	hsts := resp.Header.Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Error("expected includeSubDomains")
	}
	if !strings.Contains(hsts, "preload") {
		t.Error("expected preload")
	}
}

func TestHSTS_NotAppliedOnHTTP(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	req := &http.Request{
		// No TLS
	}

	cfg := &HSTSConfig{
		Enabled: true,
		MaxAge:  31536000,
	}

	applyHSTSHeader(resp, req, cfg)

	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("should not add HSTS header on HTTP")
	}
}

func TestHSTS_DefaultMaxAge(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	req := &http.Request{
		TLS: &tls.ConnectionState{},
	}

	cfg := &HSTSConfig{
		Enabled: true,
		// MaxAge is 0, should use default 31536000
	}

	applyHSTSHeader(resp, req, cfg)

	hsts := resp.Header.Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("expected default max-age=31536000, got %s", hsts)
	}
}
