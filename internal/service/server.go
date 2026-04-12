// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	cfgpkg "github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/middleware/callback"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/security/tlsutil"
	xhttp2 "golang.org/x/net/http2"

	"github.com/go-chi/chi/v5"
)

// Config represents the proxy server configuration (defined in config.go)
// type Config = config.ServerConfig

// ShouldBindHTTP returns true if HTTP server should be started
func ShouldBindHTTP(c Config) bool {
	return c.ProxyConfig.HTTPBindPort > 0
}

// ShouldBindHTTPS returns true if HTTPS server should be started
func ShouldBindHTTPS(c Config) bool {
	return c.ProxyConfig.HTTPSBindPort > 0
}

// ShouldBindHTTP3 returns true if HTTP/3 server should be started
func ShouldBindHTTP3(c Config) bool {
	return c.ProxyConfig.HTTP3BindPort > 0 || c.ProxyConfig.EnableHTTP3
}

// StartHTTP configures and starts the HTTP proxy server
// managers parameter should be initialized once via InitializeManagers() and shared across all servers
func StartHTTP(p ProxyConfig, m manager.Manager, callbackCache *callback.CallbackCache, handler *chi.Mux) error {
	slog.Debug("starting HTTP proxy server", "address", p.BindAddress, "port", p.HTTPBindPort)

	// Track active connections
	var activeConnCount int64
	var connMutex sync.Mutex

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", p.BindAddress, p.HTTPBindPort),
		Handler:      handler,
		ReadTimeout:  p.ReadTimeout,
		WriteTimeout: p.WriteTimeout,
		IdleTimeout:  p.IdleTimeout,
		ConnState: func(conn net.Conn, state http.ConnState) {
			connMutex.Lock()
			defer connMutex.Unlock()

			switch state {
			case http.StateNew:
				activeConnCount++
			case http.StateClosed, http.StateHijacked:
				activeConnCount--
			}
			// Update metric with current count
			metric.ActiveConnectionsSet("server", "http", activeConnCount)
		},
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			slog.Debug("HTTP connection established", "remote_addr", conn.RemoteAddr().String(), "conn_type", fmt.Sprintf("%T", conn))

			// Unified connection context — single context.WithValue instead of 3
			cc := &reqctx.ConnectionContext{
				Manager:       m,
				CallbackCache: callbackCache,
			}

			// Extract ConnectionTiming from the connection if it's wrapped
			if timingConn, ok := conn.(*tlsutil.ConnectionTiming); ok {
				slog.Debug("ConnectionTiming found in HTTP connection", "connected_at", timingConn.ConnectedAt)
				cc.ConnectionTiming = timingConn
			} else {
				slog.Debug("ConnectionTiming NOT found in HTTP connection", "conn_type", fmt.Sprintf("%T", conn))
			}

			return reqctx.SetConnectionContext(ctx, cc)
		},
	}
	if cfgpkg.HTTP2ExtendedConnectRuntimeEnabled() {
		if err := xhttp2.ConfigureServer(srv, &xhttp2.Server{}); err != nil {
			return fmt.Errorf("failed to configure HTTPS server for RFC 8441 support: %w", err)
		}
	}

	// Start graceful shutdown goroutine
	go func() {
		<-m.GetServerContext().Done()
		slog.Info("shutting down HTTP server", "address", p.BindAddress, "port", p.HTTPBindPort)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), p.GraceTime)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}
	}()

	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", srv.Addr, err)
	}
	defer listener.Close()

	// Wrap with PROXY protocol support (must be before TLS)
	if p.HAProxyProtocol != nil && p.HAProxyProtocol.Enabled {
		listener = newProxyProtocolListener(listener, p.HAProxyProtocol.TrustedCIDRs)
		slog.Info("PROXY protocol enabled on HTTP listener", "trusted_cidrs", p.HAProxyProtocol.TrustedCIDRs)
	}

	// Wrap listener with connection timing tracker to track first byte reads
	listener = tlsutil.NewTimingListener(listener)
	slog.Debug("wrapped listener with connection timing")

	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server error: %w", err)
	}

	return nil
}

// StartHTTPS configures and starts the HTTPS proxy server
// managers parameter should be initialized once via InitializeManagers() and shared across all servers
func StartHTTPS(p ProxyConfig, m manager.Manager, callbackCache *callback.CallbackCache, tlsConfig *tls.Config, handler *chi.Mux) error {
	slog.Debug("starting HTTPS proxy server", "address", p.BindAddress, "port", p.HTTPSBindPort)

	// Alt-Svc header is now handled centrally in middleware.HTTP3; avoid duplicating here

	// Get ConnState handler from connection manager
	// var connStateHandler func(net.Conn, http.ConnState)
	// if connManager != nil {
	// 	fpMiddleware := middleware.NewFingerprintMiddleware(false, middleware.WithConnectionManager(connManager))
	// 	connStateHandler = fpMiddleware.ConnStateHandler()
	// }

	// Track active HTTPS connections
	var activeHTTPSConnCount int64
	var httpsConnMutex sync.Mutex

	srv := &http.Server{
		Addr: fmt.Sprintf("%s:%d", p.BindAddress, p.HTTPSBindPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// advertise HTTP/3 if enabled and HTTP/3 port is set
			if p.EnableHTTP3 && p.HTTP3BindPort > 0 {
				w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=86400`, p.HTTP3BindPort))
			}
			handler.ServeHTTP(w, r)
		}),
		ReadTimeout:  p.ReadTimeout,
		WriteTimeout: p.WriteTimeout,
		IdleTimeout:  p.IdleTimeout,
		TLSConfig:    tlsConfig,
		ConnState: func(conn net.Conn, state http.ConnState) {
			httpsConnMutex.Lock()
			defer httpsConnMutex.Unlock()

			switch state {
			case http.StateNew:
				activeHTTPSConnCount++
			case http.StateClosed, http.StateHijacked:
				activeHTTPSConnCount--
			}
			// Update metric with current count
			metric.ActiveConnectionsSet("server", "https", activeHTTPSConnCount)
		},
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			slog.Debug("HTTPS connection established", "remote_addr", conn.RemoteAddr().String(), "conn_type", fmt.Sprintf("%T", conn))

			// Track TLS version if this is a TLS connection
			if tlsConn, ok := conn.(*tls.Conn); ok {
				tlsVersion := "unknown"
				state := tlsConn.ConnectionState()
				switch state.Version {
				case tls.VersionTLS10:
					tlsVersion = "1.0"
				case tls.VersionTLS11:
					tlsVersion = "1.1"
				case tls.VersionTLS12:
					tlsVersion = "1.2"
				case tls.VersionTLS13:
					tlsVersion = "1.3"
				}
				metric.TLSVersionUsage("server", tlsVersion)
			}

			// Unified connection context — single context.WithValue instead of 3
			cc := &reqctx.ConnectionContext{
				Manager:       m,
				CallbackCache: callbackCache,
			}

			// Try to extract ConnectionTiming - it might be wrapped by TLS
			var timingConn *tlsutil.ConnectionTiming
			if tc, ok := conn.(*tlsutil.ConnectionTiming); ok {
				timingConn = tc
			} else if tlsConn, ok := conn.(*tls.Conn); ok {
				if underlying := tlsConn.NetConn(); underlying != nil {
					if tc, ok := underlying.(*tlsutil.ConnectionTiming); ok {
						timingConn = tc
					}
				}
			}

			if timingConn != nil {
				slog.Debug("ConnectionTiming found in HTTPS connection", "connected_at", timingConn.ConnectedAt)
				cc.ConnectionTiming = timingConn
			} else {
				slog.Debug("ConnectionTiming NOT found in HTTPS connection", "conn_type", fmt.Sprintf("%T", conn))
			}

			return reqctx.SetConnectionContext(ctx, cc)
		},
	}

	// Start graceful shutdown goroutine
	go func() {
		<-m.GetServerContext().Done()
		slog.Info("shutting down HTTPS server", "address", p.BindAddress, "port", p.HTTPSBindPort)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), p.GraceTime)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTPS server shutdown error", "error", err, "address", p.BindAddress, "port", p.HTTPSBindPort)
		}
	}()

	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", srv.Addr, err)
	}
	defer listener.Close()

	// Wrap with PROXY protocol support (must be before TLS)
	if p.HAProxyProtocol != nil && p.HAProxyProtocol.Enabled {
		listener = newProxyProtocolListener(listener, p.HAProxyProtocol.TrustedCIDRs)
		slog.Info("PROXY protocol enabled on HTTPS listener", "trusted_cidrs", p.HAProxyProtocol.TrustedCIDRs)
	}

	// Wrap listener with connection timing tracker to track first byte reads
	listener = tlsutil.NewTimingListener(listener)
	slog.Debug("wrapped listener with connection timing")

	if err := srv.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTPS server error: %w", err)
	}

	return nil
}

// StartHTTP3 configures and starts the HTTP/3 proxy server
// managers parameter should be initialized once via InitializeManagers() and shared across all servers
func StartHTTP3(p ProxyConfig, m manager.Manager, callbackCache *callback.CallbackCache, tlsConfig *tls.Config, handler *chi.Mux) error {
	// Determine which port to use for HTTP/3
	http3Port := p.HTTPSBindPort
	if p.HTTP3BindPort > 0 {
		http3Port = p.HTTP3BindPort
	}
	slog.Debug("starting HTTP/3 proxy server", "bind_address", p.BindAddress, "port", http3Port)

	// Track active HTTP/3 connections
	var activeHTTP3ConnCount int64
	var http3ConnMutex sync.Mutex

	// For HTTP/3, always use ":" format to bind to all interfaces (IPv4 and IPv6)
	// The http3.Server expects ":" format for binding to all interfaces
	// Even if bind_address is "0.0.0.0", we use ":" for HTTP/3 to ensure proper QUIC binding
	var http3Addr string
	if p.BindAddress == "" || p.BindAddress == "0.0.0.0" {
		http3Addr = fmt.Sprintf(":%d", http3Port)
	} else {
		http3Addr = fmt.Sprintf("%s:%d", p.BindAddress, http3Port)
	}

	srv := &http3.Server{
		Addr:      http3Addr,
		Handler:   handler,
		TLSConfig: tlsConfig,
		Logger:    slog.Default(), // Set logger to prevent nil pointer dereference
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			slog.Debug("HTTP/3 connection established", "remote_addr", conn.RemoteAddr().String())

			// Track QUIC connection attempt (success)
			metric.QUICConnection("server", "success")

			// Track connection
			http3ConnMutex.Lock()
			activeHTTP3ConnCount++
			metric.ActiveConnectionsSet("server", "http3", activeHTTP3ConnCount)
			http3ConnMutex.Unlock()

			// Track connection close
			go func() {
				<-conn.Context().Done()
				http3ConnMutex.Lock()
				activeHTTP3ConnCount--
				metric.ActiveConnectionsSet("server", "http3", activeHTTP3ConnCount)
				http3ConnMutex.Unlock()
			}()

			// Unified connection context — single context.WithValue instead of 3
			quicTiming := tlsutil.NewQUICConnectionTiming()
			cc := &reqctx.ConnectionContext{
				Manager:          m,
				CallbackCache:    callbackCache,
				ConnectionTiming: quicTiming,
			}
			slog.Debug("QUIC timing added to context", "connected_at", quicTiming.GetConnectedAt())

			return reqctx.SetConnectionContext(ctx, cc)
		},
	}

	// Start graceful shutdown goroutine
	go func() {
		<-m.GetServerContext().Done()
		slog.Info("shutting down HTTP/3 server", "address", p.BindAddress, "port", http3Port)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), p.GraceTime)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP/3 server shutdown error", "error", err, "address", p.BindAddress, "port", http3Port)
		}
	}()

	// Track QUIC connection failures
	slog.Info("HTTP/3 server listening", "address", http3Addr, "original_bind_address", p.BindAddress)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		metric.QUICConnection("server", "failure")
		slog.Error("HTTP/3 server error", "error", err, "address", http3Addr)
		return fmt.Errorf("HTTP/3 server error: %w", err)
	}

	return nil
}

// ShouldBindHTTPSProxy returns false - HTTPS forward proxy is enterprise-only.
func ShouldBindHTTPSProxy(c HTTPSProxyConfig) bool {
	return false
}

// StartHTTPSProxyServer is a no-op in OSS - HTTPS forward proxy is enterprise-only.
func StartHTTPSProxyServer(cfg HTTPSProxyConfig, m manager.Manager) error {
	return nil
}
