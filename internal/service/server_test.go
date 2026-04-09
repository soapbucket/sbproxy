package service

import "testing"

func TestShouldBindHTTP(t *testing.T) {
	cfg := Config{}
	cfg.ProxyConfig.HTTPBindPort = 8080
	if !ShouldBindHTTP(cfg) {
		t.Fatalf("expected HTTP bind when port is set")
	}
	cfg.ProxyConfig.HTTPBindPort = 0
	if ShouldBindHTTP(cfg) {
		t.Fatalf("expected HTTP bind disabled when port is zero")
	}
}

func TestShouldBindHTTPS(t *testing.T) {
	cfg := Config{}
	cfg.ProxyConfig.HTTPSBindPort = 8443
	if !ShouldBindHTTPS(cfg) {
		t.Fatalf("expected HTTPS bind when port is set")
	}
	cfg.ProxyConfig.HTTPSBindPort = 0
	if ShouldBindHTTPS(cfg) {
		t.Fatalf("expected HTTPS bind disabled when port is zero")
	}
}

func TestShouldBindHTTP3(t *testing.T) {
	cfg := Config{}
	cfg.ProxyConfig.HTTP3BindPort = 0
	cfg.ProxyConfig.EnableHTTP3 = false
	if ShouldBindHTTP3(cfg) {
		t.Fatalf("expected HTTP/3 bind disabled when no port and disabled flag")
	}
	cfg.ProxyConfig.EnableHTTP3 = true
	if !ShouldBindHTTP3(cfg) {
		t.Fatalf("expected HTTP/3 bind enabled when flag is true")
	}
}
