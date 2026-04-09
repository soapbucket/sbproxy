package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyStatus_BasicHeader(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}

	cfg := &ProxyStatusConfig{
		Enable:    true,
		ProxyName: "myproxy",
	}

	applyProxyStatusHeader(resp, cfg)

	ps := resp.Header.Get("Proxy-Status")
	if ps != "myproxy" {
		t.Errorf("expected Proxy-Status: myproxy, got %s", ps)
	}
}

func TestProxyStatus_DefaultName(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}

	cfg := &ProxyStatusConfig{
		Enable: true,
	}

	applyProxyStatusHeader(resp, cfg)

	ps := resp.Header.Get("Proxy-Status")
	if ps != "soapbucket" {
		t.Errorf("expected Proxy-Status: soapbucket, got %s", ps)
	}
}

func TestProxyStatus_ErrorHeader(t *testing.T) {
	w := httptest.NewRecorder()

	applyProxyStatusErrorHeader(w, &ProxyStatusError{
		ProxyName: "myproxy",
		ErrorType: "connection_timeout",
		Detail:    "upstream timed out",
	})

	ps := w.Header().Get("Proxy-Status")
	if ps == "" {
		t.Fatal("expected Proxy-Status header")
	}

	if ps != `myproxy; error=connection_timeout; details="upstream timed out"` {
		t.Errorf("unexpected Proxy-Status: %s", ps)
	}
}

func TestProxyStatus_ClassifyError(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"context deadline exceeded", "connection_timeout"},
		{"connection refused", "connection_refused"},
		{"TLS handshake error", "tls_certificate_error"},
		{"no such host", "dns_error"},
		{"something else", "proxy_internal_error"},
	}

	for _, tt := range tests {
		result := classifyProxyError(tt.input)
		if result != tt.expected {
			t.Errorf("classifyProxyError(%q) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestProxyStatus_Disabled(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}

	applyProxyStatusHeader(resp, nil)
	if resp.Header.Get("Proxy-Status") != "" {
		t.Error("should not set header when nil config")
	}

	applyProxyStatusHeader(resp, &ProxyStatusConfig{Enable: false})
	if resp.Header.Get("Proxy-Status") != "" {
		t.Error("should not set header when disabled")
	}
}
