package httpkit

import (
	"net/http"
	"testing"
)

func TestClientIP_XForwardedFor(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	r.RemoteAddr = "127.0.0.1:1234"
	if ip := ClientIP(r); ip != "203.0.113.50" {
		t.Errorf("expected 203.0.113.50, got %s", ip)
	}
}

func TestClientIP_XRealIP(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Real-IP", "10.0.0.5")
	r.RemoteAddr = "127.0.0.1:1234"
	if ip := ClientIP(r); ip != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %s", ip)
	}
}

func TestClientIP_RemoteAddr(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:5678"
	if ip := ClientIP(r); ip != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip)
	}
}

func TestSplitHostPort(t *testing.T) {
	h, p := SplitHostPort("192.168.1.1:8080")
	if h != "192.168.1.1" || p != "8080" {
		t.Errorf("got %s:%s", h, p)
	}
	h, p = SplitHostPort("192.168.1.1")
	if h != "192.168.1.1" || p != "" {
		t.Errorf("got %s:%s", h, p)
	}
}
