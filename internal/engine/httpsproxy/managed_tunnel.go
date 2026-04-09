package httpsproxy

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/configloader"
)

type managedTunnelParams struct {
	engine      *Engine
	auth        *configloader.ProxyAuthResult
	proxyAction *config.HTTPSProxyAction
	target      *connectTarget
	initialCfg  *config.Config
	serverCert  *tls.Certificate
	tunnel      EstablishedTunnel
}

type managedTunnelExecutor interface {
	Supports(EstablishedTunnel) bool
	Serve(managedTunnelParams) error
	Name() string
}

type genericManagedTunnelExecutor struct{}

func (genericManagedTunnelExecutor) Name() string {
	return "generic_managed_tunnel"
}

func (genericManagedTunnelExecutor) Supports(EstablishedTunnel) bool {
	return true
}

func (genericManagedTunnelExecutor) Serve(params managedTunnelParams) error {
	hostname := params.target.Hostname
	tlsConn := wrapManagedTunnelTLS(params.tunnel, params.serverCert)
	listener := newSingleUseListener(tlsConn)
	server := params.engine.buildManagedTunnelServer(params.auth, params.proxyAction, params.target, params.initialCfg)
	startTime := time.Now()

	metricsCollector.RecordManagedTunnelEstablished(hostname)
	slog.Debug("managed tunnel serving",
		"hostname", hostname,
		"workspace_id", params.auth.WorkspaceID,
	)

	err := server.Serve(listener)
	duration := time.Since(startTime)
	bytesTransferred := listener.BytesTransferred()

	metricsCollector.RecordTunnelClosed(duration, bytesTransferred)
	metricsCollector.RecordManagedTunnelClosed(hostname, duration, bytesTransferred, 0)

	slog.Debug("managed tunnel closed",
		"hostname", hostname,
		"duration_ms", duration.Milliseconds(),
		"bytes", bytesTransferred,
	)

	if err == nil || err == http.ErrServerClosed || isExpectedManagedTunnelClosure(err) {
		return nil
	}
	return err
}

type tunnelNetConn struct {
	EstablishedTunnel
	conn ConnBackedTunnel
}

func newTunnelNetConn(tunnel EstablishedTunnel) net.Conn {
	if connBacked, ok := tunnel.(ConnBackedTunnel); ok {
		return connBacked.NetConn()
	}
	return &tunnelNetConn{EstablishedTunnel: tunnel}
}

func (c *tunnelNetConn) LocalAddr() net.Addr {
	if c.conn != nil {
		return c.conn.NetConn().LocalAddr()
	}
	return tunnelAddr("local")
}

func (c *tunnelNetConn) RemoteAddr() net.Addr {
	if c.conn != nil {
		return c.conn.NetConn().RemoteAddr()
	}
	return tunnelAddr("remote")
}

func (c *tunnelNetConn) SetDeadline(time.Time) error {
	return nil
}

func (c *tunnelNetConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *tunnelNetConn) SetWriteDeadline(time.Time) error {
	return nil
}

type tunnelAddr string

func (a tunnelAddr) Network() string { return "tunnel" }
func (a tunnelAddr) String() string  { return string(a) }

func isExpectedManagedTunnelClosure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}
