package httpsproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
)

func TestIsConnectIPRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodConnect, "https://proxy.example/ip", nil)
	r.Proto = "connect-ip"
	if !isConnectIPRequest(r) {
		t.Fatal("expected connect-ip request to be detected")
	}

	r2 := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
	r2.Proto = "HTTP/2.0"
	if isConnectIPRequest(r2) {
		t.Fatal("expected non-connect-ip request to be rejected")
	}
}

func TestParseConnectIPTarget(t *testing.T) {
	tests := []struct {
		name       string
		queryParam string
		host       string
		wantTarget string
		wantErr    bool
	}{
		{
			name:       "target from query parameter",
			queryParam: "192.168.1.1",
			host:       "proxy.example",
			wantTarget: "192.168.1.1",
		},
		{
			name:       "target from host when no query",
			queryParam: "",
			host:       "10.0.0.1",
			wantTarget: "10.0.0.1",
		},
		{
			name:       "target with port from query",
			queryParam: "10.0.0.1:8443",
			host:       "proxy.example",
			wantTarget: "10.0.0.1:8443",
		},
		{
			name:    "missing target",
			host:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "https://proxy.example/ip"
			if tt.queryParam != "" {
				url += "?target=" + tt.queryParam
			}
			r := httptest.NewRequest(http.MethodConnect, url, nil)
			r.Host = tt.host
			if tt.host == "" {
				r.Host = ""
				r.URL.Host = ""
			}

			target, err := parseConnectIPTarget(r)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if target != tt.wantTarget {
				t.Fatalf("expected target %q, got %q", tt.wantTarget, target)
			}
		})
	}
}

func TestValidateConnectIPACLs(t *testing.T) {
	tests := []struct {
		name    string
		action  *config.HTTPSProxyAction
		target  *connectTarget
		wantErr bool
	}{
		{
			name:   "nil action allows all",
			action: nil,
			target: &connectTarget{Hostname: "10.0.0.1", Port: "0"},
		},
		{
			name: "blocked hostname",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					BlockedHostnames: []string{"10.0.0.1"},
				},
			},
			target:  &connectTarget{Hostname: "10.0.0.1", Port: "0"},
			wantErr: true,
		},
		{
			name: "allowed hostname passes",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					AllowedHostnames: []string{"10.0.0.1"},
				},
			},
			target: &connectTarget{Hostname: "10.0.0.1", Port: "0"},
		},
		{
			name: "hostname not in allowed list",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					AllowedHostnames: []string{"10.0.0.2"},
				},
			},
			target:  &connectTarget{Hostname: "10.0.0.1", Port: "0"},
			wantErr: true,
		},
		{
			name: "blocked port",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					BlockedPorts: []int{8080},
				},
			},
			target:  &connectTarget{Hostname: "10.0.0.1", Port: "8080"},
			wantErr: true,
		},
		{
			name: "port zero skips port ACL",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					AllowedPorts: []int{443},
				},
			},
			target: &connectTarget{Hostname: "10.0.0.1", Port: "0"},
		},
		{
			name: "blocked CIDR",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					BlockedCIDRs: []string{"10.0.0.0/8"},
				},
			},
			target:  &connectTarget{Hostname: "10.0.0.1", Port: "0"},
			wantErr: true,
		},
		{
			name: "allowed CIDR passes",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					AllowedCIDRs: []string{"10.0.0.0/8"},
				},
			},
			target: &connectTarget{Hostname: "10.0.0.1", Port: "0"},
		},
		{
			name: "CIDR not in allowed range",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					AllowedCIDRs: []string{"192.168.0.0/16"},
				},
			},
			target:  &connectTarget{Hostname: "10.0.0.1", Port: "0"},
			wantErr: true,
		},
		{
			name: "wildcard hostname block",
			action: &config.HTTPSProxyAction{
				HTTPSProxyConfig: config.HTTPSProxyConfig{
					BlockedHostnames: []string{"*.internal.example.com"},
				},
			},
			target:  &connectTarget{Hostname: "server.internal.example.com", Port: "0"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnectIPACLs(tt.action, tt.target)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateConnectMode_ConnectIPEnabled(t *testing.T) {
	engine := New(nil, "Proxy Test")
	engine.SetListenerOptions(ListenerOptions{EnableConnectIP: true})

	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AdvancedConnect: &config.AdvancedConnectConfig{EnableConnectIP: true},
		},
	}

	reqIP := httptest.NewRequest(http.MethodConnect, "https://proxy.example/ip", nil)
	reqIP.ProtoMajor = 3
	reqIP.Proto = "connect-ip"

	if err := engine.validateConnectMode(reqIP, action); err != nil {
		t.Fatalf("expected CONNECT-IP to be allowed when enabled, got %v", err)
	}
}

func TestValidateConnectMode_ConnectIPDisabledAtListener(t *testing.T) {
	engine := New(nil, "Proxy Test")
	engine.SetListenerOptions(ListenerOptions{EnableConnectIP: false})

	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AdvancedConnect: &config.AdvancedConnectConfig{EnableConnectIP: true},
		},
	}

	reqIP := httptest.NewRequest(http.MethodConnect, "https://proxy.example/ip", nil)
	reqIP.ProtoMajor = 3
	reqIP.Proto = "connect-ip"

	if err := engine.validateConnectMode(reqIP, action); err == nil {
		t.Fatal("expected CONNECT-IP to be rejected when listener flag is disabled")
	}
}

func TestValidateConnectMode_ConnectIPDisabledAtOrigin(t *testing.T) {
	engine := New(nil, "Proxy Test")
	engine.SetListenerOptions(ListenerOptions{EnableConnectIP: true})

	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AdvancedConnect: &config.AdvancedConnectConfig{EnableConnectIP: false},
		},
	}

	reqIP := httptest.NewRequest(http.MethodConnect, "https://proxy.example/ip", nil)
	reqIP.ProtoMajor = 3
	reqIP.Proto = "connect-ip"

	if err := engine.validateConnectMode(reqIP, action); err == nil {
		t.Fatal("expected CONNECT-IP to be rejected when origin flag is disabled")
	}
}

func TestConnectIPTunnel_Relay(t *testing.T) {
	// Set up a UDP echo server for testing.
	udpServer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start UDP echo server: %v", err)
	}
	defer udpServer.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, readErr := udpServer.ReadFrom(buf)
			if readErr != nil {
				return
			}
			_, _ = udpServer.WriteTo(buf[:n], addr)
		}
	}()

	// Resolve the server address.
	serverAddr := udpServer.LocalAddr().(*net.UDPAddr)
	udpConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer udpConn.Close()

	// Create a pipe to simulate client body and response.
	clientBodyR, clientBodyW := io.Pipe()
	rec := httptest.NewRecorder()

	tunnel := &connectIPTunnel{
		body:       clientBodyR,
		writer:     rec,
		controller: nil, // NewResponseController won't work with httptest.ResponseRecorder in test
		udpConn:    udpConn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan int64, 1)
	go func() {
		done <- tunnel.relay(ctx)
	}()

	// Write a packet from the "client".
	payload := "hello-ip-tunnel"
	_, _ = clientBodyW.Write([]byte(payload))

	// Give the echo server time to respond and relay to process.
	time.Sleep(100 * time.Millisecond)

	// Close the write side to trigger relay shutdown.
	_ = clientBodyW.Close()

	select {
	case bytesTransferred := <-done:
		if bytesTransferred == 0 {
			t.Fatal("expected bytes to be transferred")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for relay to finish")
	}

	// Verify the echo response was written back to the client.
	body := rec.Body.String()
	if !strings.Contains(body, payload) {
		t.Fatalf("expected response to contain echoed payload %q, got %q", payload, body)
	}
}

func TestHandleConnectIP_ACLDenied(t *testing.T) {
	engine := &Engine{
		listenerOptions: ListenerOptions{EnableConnectIP: true},
	}

	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AdvancedConnect:  &config.AdvancedConnectConfig{EnableConnectIP: true},
			BlockedHostnames: []string{"10.0.0.1"},
		},
	}

	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example/ip?target=10.0.0.1", nil)
	req.Proto = "connect-ip"
	req.ProtoMajor = 3
	rec := httptest.NewRecorder()

	engine.handleConnectIP(rec, req, action)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
	}
}

func TestHandleConnectIP_InvalidTarget(t *testing.T) {
	engine := &Engine{
		listenerOptions: ListenerOptions{EnableConnectIP: true},
	}

	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AdvancedConnect: &config.AdvancedConnectConfig{EnableConnectIP: true},
		},
	}

	// No target parameter and empty host - should fail.
	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example/ip", nil)
	req.Proto = "connect-ip"
	req.ProtoMajor = 3
	req.Host = ""
	req.URL.Host = ""
	rec := httptest.NewRecorder()

	engine.handleConnectIP(rec, req, action)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestHandleConnectIP_NonIPTarget(t *testing.T) {
	engine := &Engine{
		listenerOptions: ListenerOptions{EnableConnectIP: true},
	}

	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AdvancedConnect: &config.AdvancedConnectConfig{EnableConnectIP: true},
		},
	}

	// A hostname (not an IP) without a port should fail the IP validation.
	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example/ip?target=not-an-ip", nil)
	req.Proto = "connect-ip"
	req.ProtoMajor = 3
	rec := httptest.NewRecorder()

	engine.handleConnectIP(rec, req, action)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for non-IP target, got %d", rec.Code)
	}
}
