// Package httpsproxy implements HTTPS CONNECT tunnel proxying for TLS passthrough and interception.
package httpsproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/configloader"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/yosida95/uritemplate/v3"
)

// Engine represents a engine.
type Engine struct {
	manager               manager.Manager
	authRealm             string
	dialContext           func(ctx context.Context, network, addr string) (net.Conn, error)
	tunnelEstablisher     TunnelEstablisher
	managedTunnelExecutor managedTunnelExecutor
	listenerOptions       ListenerOptions
	udpProxy              *masque.Proxy
}

// ListenerOptions configures advanced CONNECT behavior at the listener level.
type ListenerOptions struct {
	DisableHTTP2Connect    bool
	DisableHTTP3Connect    bool
	EnableRFC8441WebSocket bool
	EnableConnectUDP       bool
	EnableConnectIP        bool
	ConnectUDPTemplate     string
	ConnectIPTemplate      string
}

var (
	metricsCollector = config.NewMetricsCollector("")
)

// New creates and initializes a new .
func New(manager manager.Manager, authRealm string) *Engine {
	if authRealm == "" {
		authRealm = "SoapBucket Proxy"
	}
	metricsCollector.Register()
	return &Engine{
		manager:   manager,
		authRealm: authRealm,
		dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		},
		tunnelEstablisher:     classicConnectEstablisher{},
		managedTunnelExecutor: genericManagedTunnelExecutor{},
		udpProxy:              &masque.Proxy{},
	}
}

func (e *Engine) SetListenerOptions(opts ListenerOptions) {
	e.listenerOptions = opts
}

// HandleConnect performs the handle connect operation on the Engine.
func (e *Engine) HandleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	originID, apiKey, err := parseProxyAuthorization(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		metricsCollector.RecordAuthFailure()
		e.emitAuthFailure(r.Context(), "", "missing_or_invalid_proxy_authorization")
		e.sendProxyAuthRequired(w)
		return
	}

	authResult, err := configloader.AuthenticateProxyClient(r.Context(), originID, apiKey, e.manager)
	if err != nil {
		metricsCollector.RecordAuthFailure()
		e.emitAuthFailure(r.Context(), originID, "proxy_auth_failed")
		e.sendProxyAuthRequired(w)
		return
	}
	metricsCollector.RecordAuthSuccess()

	proxyAction, err := proxyProfileFromConfig(authResult.ProxyConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := proxyAction.EnsureRuntime(r.Context()); err != nil && proxyAction.CertificateSpoofing != nil && proxyAction.CertificateSpoofing.Enabled {
		metricsCollector.RecordTunnelFailed("runtime_initialization_failed")
		http.Error(w, "https proxy runtime initialization failed", http.StatusBadGateway)
		return
	}

	baseCtx := withProxyRequestData(r.Context(), authResult)

	if err := e.validateConnectMode(r, proxyAction); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if isConnectUDPRequest(r) {
		e.handleConnectUDP(w, r.WithContext(baseCtx), proxyAction)
		return
	}

	if isConnectIPRequest(r) {
		e.handleConnectIP(w, r.WithContext(baseCtx), proxyAction)
		return
	}

	target, err := parseConnectTarget(r.Host)
	if err != nil {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}

	if err := validateTargetACLs(proxyAction, target); err != nil {
		metricsCollector.RecordDestinationBlocked()
		e.emitDestinationBlocked(r.Context(), authResult, target, err.Error())
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	managedCfg, managedErr := configloader.LoadForProxyHost(baseCtx, authResult, target.Hostname, e.manager)
	if managedErr == nil {
		metricsCollector.RecordManagedTarget()
		setProxyMetadata(baseCtx, target, "managed", "")
		e.emitTargetDecision(baseCtx, authResult, target, "managed")
		e.handleManagedHost(w, r.WithContext(baseCtx), authResult, proxyAction, target, managedCfg)
		return
	}
	if !errors.Is(managedErr, configloader.ErrNotFound) {
		metricsCollector.RecordTunnelFailed("managed_lookup_failed")
		http.Error(w, managedErr.Error(), http.StatusBadGateway)
		return
	}

	resolvedAddr, privateDenied, err := validatePassthroughDestination(baseCtx, proxyAction, target)
	if err != nil {
		if privateDenied {
			metricsCollector.RecordPrivateDenied()
		} else {
			metricsCollector.RecordDestinationBlocked()
		}
		e.emitDestinationBlocked(baseCtx, authResult, target, err.Error())
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	metricsCollector.RecordUnmanagedTarget()
	setProxyMetadata(baseCtx, target, "passthrough", resolvedAddr)
	e.emitTargetDecision(baseCtx, authResult, target, "unmanaged")
	e.handlePassthrough(w, r.WithContext(baseCtx), target, resolvedAddr)
}

func isConnectUDPRequest(r *http.Request) bool {
	return strings.EqualFold(r.Proto, "connect-udp")
}

func isConnectIPRequest(r *http.Request) bool {
	return strings.EqualFold(r.Proto, "connect-ip")
}

func (e *Engine) validateConnectMode(r *http.Request, proxyAction *config.HTTPSProxyAction) error {
	if proxyAction == nil {
		return nil
	}
	ac := proxyAction.AdvancedConnect
	if ac == nil {
		ac = &config.AdvancedConnectConfig{}
	}

	switch r.ProtoMajor {
	case 2:
		if e.listenerOptions.DisableHTTP2Connect || ac.DisableHTTP2Connect {
			return fmt.Errorf("HTTP/2 CONNECT is disabled")
		}
	case 3:
		if e.listenerOptions.DisableHTTP3Connect || ac.DisableHTTP3Connect {
			return fmt.Errorf("HTTP/3 CONNECT is disabled")
		}
	}

	if isConnectUDPRequest(r) {
		if !e.listenerOptions.EnableConnectUDP || !ac.EnableConnectUDP {
			return fmt.Errorf("CONNECT-UDP is not enabled")
		}
	}
	if isConnectIPRequest(r) {
		if !e.listenerOptions.EnableConnectIP || !ac.EnableConnectIP {
			return fmt.Errorf("CONNECT-IP is not enabled")
		}
	}

	return nil
}

func (e *Engine) handleConnectUDP(w http.ResponseWriter, r *http.Request, proxyAction *config.HTTPSProxyAction) {
	template, err := e.connectUDPTemplate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req, err := masque.ParseRequest(r, template)
	if err != nil {
		var parseErr *masque.RequestParseError
		if errors.As(err, &parseErr) {
			http.Error(w, parseErr.Error(), parseErr.HTTPStatus)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	target, err := parseConnectTarget(req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateTargetACLs(proxyAction, target); err != nil {
		metricsCollector.RecordDestinationBlocked()
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if _, privateDenied, err := validatePassthroughDestination(r.Context(), proxyAction, target); err != nil {
		if privateDenied {
			metricsCollector.RecordPrivateDenied()
		} else {
			metricsCollector.RecordDestinationBlocked()
		}
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if err := e.udpProxy.Proxy(w, req); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func (e *Engine) connectUDPTemplate(r *http.Request) (*uritemplate.Template, error) {
	templateStr := e.listenerOptions.ConnectUDPTemplate
	if templateStr == "" {
		templateStr = "https://" + r.Host + r.URL.Path + "?h={target_host}&p={target_port}"
	}
	return uritemplate.New(templateStr)
}

func (e *Engine) handleConnectIP(w http.ResponseWriter, r *http.Request, proxyAction *config.HTTPSProxyAction) {
	target, err := parseConnectIPTarget(r)
	if err != nil {
		metricsCollector.RecordTypedTunnelFailed("connect-ip", "invalid_request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ct := &connectTarget{
		Host:      target,
		Hostname:  target,
		Port:      "0",
		Authority: target,
	}

	// Parse as host:port if possible, otherwise treat as bare IP/hostname.
	if host, port, splitErr := net.SplitHostPort(target); splitErr == nil {
		ct.Hostname = strings.Trim(host, "[]")
		ct.Port = port
		ct.Authority = net.JoinHostPort(ct.Hostname, port)
	} else {
		// Bare IP address - no port. Validate as IP.
		if ip := net.ParseIP(target); ip == nil {
			metricsCollector.RecordTypedTunnelFailed("connect-ip", "invalid_target_ip")
			metricsCollector.RecordACLDenied("connect-ip", "invalid_target")
			http.Error(w, "CONNECT-IP target must be a valid IP address", http.StatusBadRequest)
			return
		}
	}

	if err := validateConnectIPACLs(proxyAction, ct); err != nil {
		metricsCollector.RecordDestinationBlocked()
		metricsCollector.RecordTypedTunnelFailed("connect-ip", "acl_denied")
		metricsCollector.RecordACLDenied("connect-ip", err.Error())
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	metricsCollector.RecordACLAllowed("connect-ip")

	// Validate the destination is not a private/metadata address unless explicitly allowed.
	if _, privateDenied, valErr := validatePassthroughDestination(r.Context(), proxyAction, ct); valErr != nil {
		if privateDenied {
			metricsCollector.RecordPrivateDenied()
		} else {
			metricsCollector.RecordDestinationBlocked()
		}
		metricsCollector.RecordTypedTunnelFailed("connect-ip", "destination_validation_failed")
		metricsCollector.RecordACLDenied("connect-ip", valErr.Error())
		http.Error(w, valErr.Error(), http.StatusForbidden)
		return
	}

	// Establish the IP tunnel using UDP as the transport layer.
	// RFC 9298 CONNECT-IP encapsulates IP packets in HTTP datagrams.
	// In a proxy context, we relay packets over UDP to approximate IP-level tunneling
	// without requiring raw socket privileges.
	metricsCollector.RecordTypedTunnelEstablished("connect-ip")
	metricsCollector.RecordTunnelEstablished()
	startTime := time.Now()

	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	relayAddr := ct.Authority
	if ct.Port == "0" {
		// Default to UDP relay on an ephemeral port when no port specified.
		relayAddr = net.JoinHostPort(ct.Hostname, "443")
	}

	udpAddr, resolveErr := net.ResolveUDPAddr("udp", relayAddr)
	if resolveErr != nil {
		metricsCollector.RecordTypedTunnelFailed("connect-ip", "udp_resolve_failed")
		// Already sent 200, cannot send error status. Log and return.
		return
	}

	udpConn, dialErr := net.DialUDP("udp", nil, udpAddr)
	if dialErr != nil {
		metricsCollector.RecordTypedTunnelFailed("connect-ip", "udp_dial_failed")
		return
	}
	defer udpConn.Close()

	tunnel := &connectIPTunnel{
		body:       r.Body,
		writer:     w,
		controller: rc,
		udpConn:    udpConn,
	}

	bytesTransferred := tunnel.relay(r.Context())

	duration := time.Since(startTime)
	metricsCollector.RecordTunnelClosed(duration, bytesTransferred)
	metricsCollector.RecordTypedTunnelClosed("connect-ip", duration, bytesTransferred)
}

// parseConnectIPTarget extracts the target IP from a CONNECT-IP request.
// RFC 9298 uses URI templates; the target is extracted from query parameters
// or the request path.
func parseConnectIPTarget(r *http.Request) (string, error) {
	// Check query parameters first (standard URI template expansion).
	if target := r.URL.Query().Get("target"); target != "" {
		return target, nil
	}
	// Fall back to extracting from :authority or Host.
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host == "" {
		return "", fmt.Errorf("missing CONNECT-IP target")
	}
	return host, nil
}

// validateConnectIPACLs validates CONNECT-IP targets against the proxy ACL configuration.
// It reuses the same hostname/port/CIDR rules as CONNECT-TCP but also validates that
// the target is a valid IP address when no port is specified.
func validateConnectIPACLs(proxyAction *config.HTTPSProxyAction, target *connectTarget) error {
	if proxyAction == nil || target == nil {
		return nil
	}

	// For CONNECT-IP, blocked hostnames still apply (could be IP-based patterns).
	if hostnameMatches(proxyAction.BlockedHostnames, target.Hostname) {
		return fmt.Errorf("destination %s is blocked", target.Hostname)
	}
	if len(proxyAction.AllowedHostnames) > 0 && !hostnameMatches(proxyAction.AllowedHostnames, target.Hostname) {
		return fmt.Errorf("destination %s is not allowed", target.Hostname)
	}

	// Port-based ACLs only apply when a port is specified.
	if target.Port != "0" {
		if portBlocked(proxyAction.BlockedPorts, target.Port) {
			return fmt.Errorf("destination port %s is blocked", target.Port)
		}
		if len(proxyAction.AllowedPorts) > 0 && !portBlocked(proxyAction.AllowedPorts, target.Port) {
			return fmt.Errorf("destination port %s is not allowed", target.Port)
		}
	}

	// CIDR-based validation for IP targets.
	ip := net.ParseIP(target.Hostname)
	if ip != nil {
		blockedNetworks := parseCIDRs(proxyAction.BlockedCIDRs)
		if cidrMatches(blockedNetworks, ip) {
			return fmt.Errorf("destination IP %s is blocked by CIDR rule", ip.String())
		}
		if len(proxyAction.AllowedCIDRs) > 0 {
			allowedNetworks := parseCIDRs(proxyAction.AllowedCIDRs)
			if !cidrMatches(allowedNetworks, ip) {
				return fmt.Errorf("destination IP %s is not in allowed CIDRs", ip.String())
			}
		}
	}

	return nil
}

// connectIPTunnel relays IP-level traffic between the HTTP datagram stream
// and a UDP connection to the target. This approximates RFC 9298 IP-level
// tunneling without requiring raw socket privileges.
type connectIPTunnel struct {
	body       io.ReadCloser
	writer     http.ResponseWriter
	controller *http.ResponseController
	udpConn    *net.UDPConn
}

func (t *connectIPTunnel) relay(ctx context.Context) int64 {
	var wg sync.WaitGroup
	var total atomic.Int64
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Client -> Target: read from HTTP body, write to UDP.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := t.body.Read(buf)
			if n > 0 {
				written, writeErr := t.udpConn.Write(buf[:n])
				if written > 0 {
					total.Add(int64(written))
				}
				if writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Target -> Client: read from UDP, write to HTTP response.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			deadline := time.Now().Add(1 * time.Second)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			_ = t.udpConn.SetReadDeadline(deadline)
			n, err := t.udpConn.Read(buf)
			if n > 0 {
				written, writeErr := t.writer.Write(buf[:n])
				if written > 0 {
					total.Add(int64(written))
				}
				if writeErr != nil {
					return
				}
				if t.controller != nil {
					_ = t.controller.Flush()
				}
			}
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
		}
	}()

	wg.Wait()
	return total.Load()
}

func (e *Engine) sendProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%s"`, e.authRealm))
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = io.WriteString(w, "Proxy Authentication Required")
}

func parseProxyAuthorization(auth string) (string, string, error) {
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return "", "", errors.New("missing proxy authorization")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("invalid proxy credentials")
	}
	return parts[0], parts[1], nil
}

type connectTarget struct {
	Host      string
	Hostname  string
	Port      string
	Authority string
}

func parseConnectTarget(target string) (*connectTarget, error) {
	if target == "" {
		return nil, errors.New("missing target")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = target
			port = "443"
		} else {
			return nil, err
		}
	}
	if host == "" || port == "" {
		return nil, errors.New("invalid target")
	}
	return &connectTarget{
		Host:      target,
		Hostname:  strings.Trim(host, "[]"),
		Port:      port,
		Authority: net.JoinHostPort(strings.Trim(host, "[]"), port),
	}, nil
}

func proxyProfileFromConfig(cfg *config.Config) (*config.HTTPSProxyAction, error) {
	if cfg == nil {
		return nil, errors.New("proxy config not loaded")
	}
	action, ok := cfg.ActionConfig().(*config.HTTPSProxyAction)
	if !ok {
		return nil, fmt.Errorf("origin %s is not configured with https_proxy action", cfg.ID)
	}
	return action, nil
}

func withProxyRequestData(ctx context.Context, auth *configloader.ProxyAuthResult) context.Context {
	requestData := reqctx.GetRequestData(ctx)
	if requestData == nil {
		requestData = reqctx.NewRequestData()
	}
	requestData.ProxyKeyID = auth.ProxyKeyID
	requestData.ProxyKeyName = auth.ProxyKeyName
	if requestData.Env == nil {
		requestData.Env = make(map[string]any)
	}
	if requestData.Data == nil {
		requestData.Data = make(map[string]any)
	}
	requestData.Env["origin_id"] = auth.OriginID
	requestData.Env["workspace_id"] = auth.WorkspaceID
	requestData.Data["_https_proxy_profile_cfg"] = auth.ProxyConfig
	requestData.Data["proxy_auth_origin_id"] = auth.OriginID
	requestData.Data["proxy_target_mode"] = "unknown"
	return reqctx.SetRequestData(ctx, requestData)
}

func (e *Engine) handlePassthrough(w http.ResponseWriter, r *http.Request, target *connectTarget, resolvedAddr string) {
	clientTunnel, err := e.establishClientTunnel(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientTunnel.Close()

	metricsCollector.RecordTunnelEstablished()
	e.emitTunnelLifecycle(r.Context(), reqctx.GetRequestData(r.Context()), target, "passthrough")
	startTime := time.Now()

	upstreamAddr := resolvedAddr
	if upstreamAddr == "" {
		upstreamAddr = target.Authority
	}
	upstream, err := e.dialContext(r.Context(), "tcp", upstreamAddr)
	if err != nil {
		metricsCollector.RecordTunnelFailed("upstream_dial_failed")
		return
	}
	defer upstream.Close()

	bytesTransferred := copyUntilDone(clientTunnel, upstream)
	metricsCollector.RecordTunnelClosed(time.Since(startTime), bytesTransferred)
}

func (e *Engine) handleManagedHost(w http.ResponseWriter, r *http.Request, auth *configloader.ProxyAuthResult, proxyAction *config.HTTPSProxyAction, target *connectTarget, initialCfg *config.Config) {
	if proxyAction.CertificateSpoofing == nil || !proxyAction.CertificateSpoofing.Enabled {
		metricsCollector.RecordTunnelFailed("managed_host_requires_mitm")
		e.emitMITMFailure(r.Context(), auth, target, "managed host requires certificate_spoofing.enabled=true")
		http.Error(w, "managed hosts require certificate_spoofing.enabled=true", http.StatusBadGateway)
		return
	}

	clientTunnel, err := e.establishClientTunnel(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientTunnel.Close()

	certManager := proxyAction.CertificateManager()
	if certManager == nil {
		e.emitMITMFailure(r.Context(), auth, target, "certificate manager not initialized")
		return
	}
	cacheHit := false
	if proxyAction.MITMCache != nil {
		_, cacheHit = proxyAction.MITMCache.Get(target.Hostname)
	}
	if cacheHit {
		metricsCollector.RecordCertCacheHit()
	} else {
		metricsCollector.RecordCertCacheMiss()
	}
	serverCert, err := certManager.GetOrGenerateCertificate(target.Hostname, proxyAction.MITMCache)
	if err != nil {
		metricsCollector.RecordTunnelFailed("certificate_generation_failed")
		e.emitMITMFailure(r.Context(), auth, target, err.Error())
		return
	}
	e.emitCertificateGenerated(r.Context(), auth, target, cacheHit)

	err = e.executeManagedTunnel(r.Context(), auth, proxyAction, target, initialCfg, serverCert, clientTunnel)
	if err != nil {
		return
	}
	metricsCollector.RecordTunnelEstablished()
	e.emitTunnelLifecycle(r.Context(), reqctx.GetRequestData(r.Context()), target, "managed")
}

func (e *Engine) establishClientTunnel(w http.ResponseWriter, r *http.Request) (EstablishedTunnel, error) {
	establisher := e.selectTunnelEstablisher(r)
	return establisher.Establish(w, r)
}

func (e *Engine) selectTunnelEstablisher(r *http.Request) TunnelEstablisher {
	if r != nil {
		switch r.ProtoMajor {
		case 2:
			return streamConnectEstablisher{transport: TunnelTransportExtendedConnectHTTP2}
		case 3:
			return streamConnectEstablisher{transport: TunnelTransportExtendedConnectHTTP3}
		}
	}
	if e.tunnelEstablisher == nil {
		return classicConnectEstablisher{}
	}
	return e.tunnelEstablisher
}

func copyUntilDone(a io.ReadWriteCloser, b io.ReadWriteCloser) int64 {
	var wg sync.WaitGroup
	var total atomic.Int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(a, b)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
			slog.Debug("tunnel copy error", "direction", "upstream->client", "err", err, "bytes", n)
		}
		closeWrite(a)
		total.Add(n)
	}()
	go func() {
		defer wg.Done()
		n, err := io.Copy(b, a)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
			slog.Debug("tunnel copy error", "direction", "client->upstream", "err", err, "bytes", n)
		}
		closeWrite(b)
		total.Add(n)
	}()
	wg.Wait()
	return total.Load()
}

func closeWrite(v any) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := v.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (e *Engine) executeManagedTunnel(ctx context.Context, auth *configloader.ProxyAuthResult, proxyAction *config.HTTPSProxyAction, target *connectTarget, initialCfg *config.Config, serverCert *tls.Certificate, tunnel EstablishedTunnel) error {
	executor := e.selectManagedTunnelExecutor(tunnel)
	if executor == nil {
		metricsCollector.RecordTunnelFailed("managed_tunnel_requires_net_conn")
		e.emitMITMFailure(ctx, auth, target, "managed tunnel transport does not expose a supported execution model")
		return nil
	}

	return executor.Serve(managedTunnelParams{
		engine:      e,
		auth:        auth,
		proxyAction: proxyAction,
		target:      target,
		initialCfg:  initialCfg,
		serverCert:  serverCert,
		tunnel:      tunnel,
	})
}

func (e *Engine) selectManagedTunnelExecutor(tunnel EstablishedTunnel) managedTunnelExecutor {
	if e.managedTunnelExecutor != nil && e.managedTunnelExecutor.Supports(tunnel) {
		return e.managedTunnelExecutor
	}
	return nil
}

func wrapManagedTunnelTLS(tunnel EstablishedTunnel, serverCert *tls.Certificate) *tls.Conn {
	return tls.Server(newTunnelNetConn(tunnel), &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS12,
	})
}

func (e *Engine) buildManagedTunnelServer(auth *configloader.ProxyAuthResult, proxyAction *config.HTTPSProxyAction, target *connectTarget, initialCfg *config.Config) *http.Server {
	return &http.Server{
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			req = req.Clone(withProxyRequestData(req.Context(), auth))
			req.Host = target.Hostname
			req.URL.Scheme = "https"
			req.URL.Host = target.Authority

			cfg, err := configloader.LoadForProxyRequest(req, auth.WorkspaceID, e.manager)
			if err != nil {
				if initialCfg != nil && initialCfg.WorkspaceID == auth.WorkspaceID && !initialCfg.Disabled {
					cfg = initialCfg
				} else {
					http.Error(rw, "managed target config not available", http.StatusBadGateway)
					return
				}
			}

			if registry := proxyAction.AIRegistry(); registry != nil {
				if providerType, ok := matchAIRequest(registry, target, req.URL.Path); ok {
					metricsCollector.RecordAIProviderDetected(providerType)
					if aiCfg, loadErr := configloader.LoadConfigByID(req.Context(), proxyAction.AIProxyOriginID, e.manager); loadErr == nil && aiCfg != nil {
						cfg = aiCfg
						metricsCollector.RecordAIProviderBypassed(providerType)
						setAIProxyRerouteMetadata(req.Context(), proxyAction.AIProxyOriginID)
					}
					requestData := reqctx.GetRequestData(req.Context())
					if requestData != nil {
						if requestData.AIUsage == nil {
							requestData.AIUsage = &reqctx.AIUsage{}
						}
						requestData.AIUsage.Provider = providerType
					}
				}
			}

			applyProxyProfileToManagedConfig(cfg, proxyAction)
			requestStart := time.Now()
			slog.Debug("tunnel: proxying request",
				"method", req.Method,
				"host", req.Host,
				"path", req.URL.Path,
				"workspace_id", auth.WorkspaceID,
			)
			trackingWriter := &tunnelResponseWriter{
				responseTrackingWriter: responseTrackingWriter{ResponseWriter: rw, statusCode: http.StatusOK},
				hostname:               target.Hostname,
			}
			cfg.ServeHTTP(trackingWriter, req)
			duration := time.Since(requestStart)
			slog.Debug("tunnel: request complete",
				"method", req.Method,
				"host", req.Host,
				"path", req.URL.Path,
				"status", trackingWriter.statusCode,
				"bytes_written", trackingWriter.bytesWritten,
				"duration_ms", duration.Milliseconds(),
			)
			metricsCollector.RecordManagedTunnelRequest(target.Hostname, trackingWriter.statusCode, duration, trackingWriter.bytesWritten)
			if requestData := reqctx.GetRequestData(req.Context()); requestData != nil && requestData.AIUsage != nil && requestData.AIUsage.Provider != "" {
				populateAIUsageFromBody(requestData, &trackingWriter.responseTrackingWriter)
				provider := requestData.AIUsage.Provider
				metricsCollector.RecordDataTransfer(provider, req.ContentLength, trackingWriter.bytesWritten)
				if trackingWriter.statusCode >= 400 {
					metricsCollector.RecordProviderError(provider)
				}
				metricsCollector.RecordRequestLatency(provider, time.Since(requestStart))
				metricsCollector.RecordEstimatedCost(provider, requestData.AIUsage.CostUSD)
			}
		}),
		ReadHeaderTimeout: 30 * time.Second,
	}
}

type observedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
	read    atomic.Int64
	written atomic.Int64
}

// Read performs the read operation on the observedConn.
func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.read.Add(int64(n))
	}
	return n, err
}

// Write performs the write operation on the observedConn.
func (c *observedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.written.Add(int64(n))
	}
	return n, err
}

// BytesTransferred performs the bytes transferred operation on the observedConn.
func (c *observedConn) BytesTransferred() int64 {
	return c.read.Load() + c.written.Load()
}

// Close releases resources held by the observedConn.
func (c *observedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

type singleUseListener struct {
	conn   net.Conn
	obs    *observedConn
	done   chan struct{}
	served bool
	mu     sync.Mutex
}

func newSingleUseListener(conn net.Conn) *singleUseListener {
	l := &singleUseListener{done: make(chan struct{})}
	l.obs = &observedConn{
		Conn: conn,
		onClose: func() {
			l.Close()
		},
	}
	l.conn = l.obs
	return l
}

// Accept performs the accept operation on the singleUseListener.
func (l *singleUseListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.served {
		l.served = true
		conn := l.conn
		l.mu.Unlock()
		return conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

// Close releases resources held by the singleUseListener.
func (l *singleUseListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

// Addr performs the addr operation on the singleUseListener.
func (l *singleUseListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

// BytesTransferred performs the bytes transferred operation on the singleUseListener.
func (l *singleUseListener) BytesTransferred() int64 {
	if l.obs == nil {
		return 0
	}
	return l.obs.BytesTransferred()
}

func validateTargetACLs(proxyAction *config.HTTPSProxyAction, target *connectTarget) error {
	if proxyAction == nil || target == nil {
		return nil
	}

	if portBlocked(proxyAction.BlockedPorts, target.Port) {
		return fmt.Errorf("destination port %s is blocked", target.Port)
	}
	if len(proxyAction.AllowedPorts) > 0 && !portBlocked(proxyAction.AllowedPorts, target.Port) {
		return fmt.Errorf("destination port %s is not allowed", target.Port)
	}
	if len(proxyAction.AllowedPorts) == 0 && len(proxyAction.BlockedPorts) == 0 && target.Port != "443" {
		return fmt.Errorf("destination port %s is not allowed by default", target.Port)
	}
	if hostnameMatches(proxyAction.BlockedHostnames, target.Hostname) {
		return fmt.Errorf("destination host %s is blocked", target.Hostname)
	}
	if len(proxyAction.AllowedHostnames) > 0 && !hostnameMatches(proxyAction.AllowedHostnames, target.Hostname) {
		return fmt.Errorf("destination host %s is not allowed", target.Hostname)
	}
	return nil
}

func portBlocked(ports []int, port string) bool {
	for _, allowed := range ports {
		if fmt.Sprintf("%d", allowed) == port {
			return true
		}
	}
	return false
}

func hostnameMatches(patterns []string, hostname string) bool {
	host := strings.ToLower(hostname)
	for _, raw := range patterns {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		if pattern == "" {
			continue
		}
		if pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

func validatePassthroughDestination(ctx context.Context, proxyAction *config.HTTPSProxyAction, target *connectTarget) (string, bool, error) {
	if proxyAction == nil || target == nil {
		return "", false, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, target.Hostname)
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve destination host: %w", err)
	}
	allowedNetworks := parseCIDRs(proxyAction.AllowedCIDRs)
	blockedNetworks := parseCIDRs(proxyAction.BlockedCIDRs)
	for _, ipAddr := range ips {
		ip := ipAddr.IP
		if isMetadataIP(ip) {
			return "", true, fmt.Errorf("metadata service destinations are not allowed")
		}
		if !proxyAction.AllowLoopback && ip.IsLoopback() {
			return "", true, fmt.Errorf("loopback destinations are not allowed")
		}
		if !proxyAction.AllowPrivateNetworks && ip.IsPrivate() {
			return "", true, fmt.Errorf("private network destinations are not allowed")
		}
		if !proxyAction.AllowLinkLocal && (ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()) {
			return "", true, fmt.Errorf("link-local destinations are not allowed")
		}
		if cidrMatches(blockedNetworks, ip) {
			return "", false, fmt.Errorf("destination IP %s is blocked", ip.String())
		}
		if len(allowedNetworks) > 0 && !cidrMatches(allowedNetworks, ip) {
			continue
		}
		return net.JoinHostPort(ip.String(), target.Port), false, nil
	}
	if len(allowedNetworks) > 0 {
		return "", false, fmt.Errorf("destination IP is not in allowed CIDRs")
	}
	return "", false, fmt.Errorf("no approved destination IPs resolved")
}

func parseCIDRs(values []string) []*net.IPNet {
	var result []*net.IPNet
	for _, value := range values {
		_, network, err := net.ParseCIDR(strings.TrimSpace(value))
		if err == nil && network != nil {
			result = append(result, network)
		}
	}
	return result
}

func cidrMatches(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isMetadataIP(ip net.IP) bool {
	return ip != nil && ip.String() == "169.254.169.254"
}

func applyProxyProfileToManagedConfig(cfg *config.Config, proxyAction *config.HTTPSProxyAction) {
	if cfg == nil || proxyAction == nil {
		return
	}

	switch action := cfg.ActionConfig().(type) {
	case *config.Proxy:
		action.SkipTLSVerifyHost = !proxyAction.TLS.VerifyCertificate
		action.MinTLSVersion = proxyAction.TLS.MinVersion
		action.CertificatePinning = proxyAction.CertificatePinning
		if proxyAction.MTLSClientCertFile != "" {
			action.MTLSClientCertFile = proxyAction.MTLSClientCertFile
			action.MTLSClientKeyFile = proxyAction.MTLSClientKeyFile
			action.MTLSCACertFile = proxyAction.MTLSCACertFile
		}
		if proxyAction.MTLSClientCertData != "" {
			action.MTLSClientCertData = proxyAction.MTLSClientCertData
			action.MTLSClientKeyData = proxyAction.MTLSClientKeyData
			action.MTLSCACertData = proxyAction.MTLSCACertData
		}
		action.RefreshTransport()
	case *config.LoadBalancerTypedConfig:
		action.ApplyHTTPSProxyProfile(proxyAction)
	case *config.GraphQLAction:
		action.SkipTLSVerifyHost = !proxyAction.TLS.VerifyCertificate
		action.MinTLSVersion = proxyAction.TLS.MinVersion
		action.CertificatePinning = proxyAction.CertificatePinning
		if proxyAction.MTLSClientCertFile != "" {
			action.MTLSClientCertFile = proxyAction.MTLSClientCertFile
			action.MTLSClientKeyFile = proxyAction.MTLSClientKeyFile
			action.MTLSCACertFile = proxyAction.MTLSCACertFile
		}
		if proxyAction.MTLSClientCertData != "" {
			action.MTLSClientCertData = proxyAction.MTLSClientCertData
			action.MTLSClientKeyData = proxyAction.MTLSClientKeyData
			action.MTLSCACertData = proxyAction.MTLSCACertData
		}
		action.RefreshTransport()
	case *config.GRPCAction:
		action.SkipTLSVerifyHost = !proxyAction.TLS.VerifyCertificate
		action.MinTLSVersion = proxyAction.TLS.MinVersion
		action.CertificatePinning = proxyAction.CertificatePinning
		if proxyAction.MTLSClientCertFile != "" {
			action.MTLSClientCertFile = proxyAction.MTLSClientCertFile
			action.MTLSClientKeyFile = proxyAction.MTLSClientKeyFile
			action.MTLSCACertFile = proxyAction.MTLSCACertFile
		}
		if proxyAction.MTLSClientCertData != "" {
			action.MTLSClientCertData = proxyAction.MTLSClientCertData
			action.MTLSClientKeyData = proxyAction.MTLSClientKeyData
			action.MTLSCACertData = proxyAction.MTLSCACertData
		}
		action.RefreshTransport()
	}
}

func matchAIRequest(registry *config.AIRegistry, target *connectTarget, path string) (string, bool) {
	if registry == nil || target == nil {
		return "", false
	}
	provider, providerType, ok := registry.MatchHost(target.Hostname)
	if !ok || provider == nil {
		return "", false
	}
	if len(provider.Ports) > 0 {
		port, err := strconv.Atoi(target.Port)
		if err != nil {
			return "", false
		}
		matched := false
		for _, p := range provider.Ports {
			if p == port {
				matched = true
				break
			}
		}
		if !matched {
			return "", false
		}
	}
	if len(provider.Endpoints) > 0 {
		if matchedProvider, matchedType, ok := registry.MatchEndpoint(path); !ok || matchedProvider == nil || matchedType != providerType {
			return "", false
		}
	}
	return providerType, true
}

type responseTrackingWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	bodyBuffer   bytes.Buffer
	bodyLimit    int64
}

// WriteHeader performs the write header operation on the responseTrackingWriter.
func (w *responseTrackingWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write performs the write operation on the responseTrackingWriter.
func (w *responseTrackingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += int64(n)
	limit := w.bodyLimit
	if limit == 0 {
		limit = 1 << 20
	}
	remaining := int(limit) - w.bodyBuffer.Len()
	if remaining > 0 {
		if remaining > n {
			remaining = n
		}
		w.bodyBuffer.Write(p[:remaining])
	}
	return n, err
}

// Flush performs the flush operation on the responseTrackingWriter.
func (w *responseTrackingWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack performs the hijack operation on the responseTrackingWriter.
func (w *responseTrackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// BodyBytes performs the body bytes operation on the responseTrackingWriter.
func (w *responseTrackingWriter) BodyBytes() []byte {
	return w.bodyBuffer.Bytes()
}

// tunnelResponseWriter wraps responseTrackingWriter and injects the
// X-Proxied-Via header on the first call to WriteHeader, so downstream
// clients can identify that the response was served through the CONNECT tunnel.
type tunnelResponseWriter struct {
	responseTrackingWriter
	hostname    string
	headersSent bool
}

// WriteHeader injects the X-Proxied-Via header before forwarding to the
// underlying writer.
func (w *tunnelResponseWriter) WriteHeader(statusCode int) {
	if !w.headersSent {
		w.headersSent = true
		w.ResponseWriter.Header().Set("X-Proxied-Via", "soapbucket-tunnel")
	}
	w.responseTrackingWriter.WriteHeader(statusCode)
}

// Write ensures headers are sent (with the tunnel header) before writing the body.
func (w *tunnelResponseWriter) Write(p []byte) (int, error) {
	if !w.headersSent {
		w.headersSent = true
		w.ResponseWriter.Header().Set("X-Proxied-Via", "soapbucket-tunnel")
	}
	return w.responseTrackingWriter.Write(p)
}

func (e *Engine) emitAuthFailure(ctx context.Context, originID string, reason string) {
	var originCfg *config.Config
	workspaceID := ""
	if originID != "" {
		if cfg, err := configloader.LoadConfigByID(ctx, originID, e.manager); err == nil && cfg != nil {
			originCfg = cfg
			workspaceID = cfg.WorkspaceID
		}
	}
	if workspaceID == "" || !shouldEmitProxyEvent(originCfg, "https_proxy.auth.failed") {
		_ = events.Publish(events.SystemEvent{
			Type:      events.EventHTTPSProxyAuthFailed,
			Severity:  events.SeverityWarning,
			Timestamp: time.Now().UTC(),
			Source:    "https_proxy",
			Data: map[string]any{
				"origin_id": originID,
				"reason":    reason,
			},
		})
		return
	}
	event := &events.HTTPSProxyAuthFailure{
		EventBase: events.NewBase("https_proxy.auth.failed", events.SeverityWarning, workspaceID, reqctx.GetRequestID(ctx)),
		Reason:    reason,
	}
	event.Origin.OriginID = originID
	event.Origin.WorkspaceID = workspaceID
	events.Emit(ctx, workspaceID, event)
}

func (e *Engine) emitTargetDecision(ctx context.Context, auth *configloader.ProxyAuthResult, target *connectTarget, decision string) {
	if auth == nil || auth.WorkspaceID == "" {
		return
	}
	eventType := "https_proxy.target." + decision
	if !shouldEmitProxyEvent(auth.ProxyConfig, eventType) {
		return
	}
	event := &events.HTTPSProxyTargetDecision{
		EventBase: events.NewBase(eventType, events.SeverityInfo, auth.WorkspaceID, reqctx.GetRequestID(ctx)),
		Target:    target.Authority,
		Decision:  decision,
	}
	event.Origin.OriginID = auth.OriginID
	event.Origin.WorkspaceID = auth.WorkspaceID
	events.Emit(ctx, auth.WorkspaceID, event)
}

func (e *Engine) emitTunnelLifecycle(ctx context.Context, requestData *reqctx.RequestData, target *connectTarget, mode string) {
	var proxyCfg *config.Config
	workspaceID := ""
	originID := ""
	if requestData != nil {
		if cfgAny, ok := requestData.Data["_https_proxy_profile_cfg"].(*config.Config); ok {
			proxyCfg = cfgAny
		}
		if v, ok := requestData.Env["workspace_id"].(string); ok {
			workspaceID = v
		}
		if v, ok := requestData.Env["origin_id"].(string); ok {
			originID = v
		}
	}
	if workspaceID == "" {
		return
	}
	eventType := "https_proxy." + mode + ".started"
	if !shouldEmitProxyEvent(proxyCfg, eventType) {
		return
	}
	event := &events.HTTPSProxyTunnelLifecycle{
		EventBase: events.NewBase(eventType, events.SeverityInfo, workspaceID, reqctx.GetRequestID(ctx)),
		Target:    target.Authority,
		Mode:      mode,
	}
	event.Origin.OriginID = originID
	event.Origin.WorkspaceID = workspaceID
	events.Emit(ctx, workspaceID, event)
}

func (e *Engine) emitMITMFailure(ctx context.Context, auth *configloader.ProxyAuthResult, target *connectTarget, reason string) {
	if auth == nil || auth.WorkspaceID == "" || !shouldEmitProxyEvent(auth.ProxyConfig, "https_proxy.mitm.handshake_failed") {
		return
	}
	event := &events.HTTPSProxyMITMFailure{
		EventBase: events.NewBase("https_proxy.mitm.handshake_failed", events.SeverityError, auth.WorkspaceID, reqctx.GetRequestID(ctx)),
		Target:    target.Authority,
		Reason:    reason,
	}
	event.Origin.OriginID = auth.OriginID
	event.Origin.WorkspaceID = auth.WorkspaceID
	events.Emit(ctx, auth.WorkspaceID, event)
}

func (e *Engine) emitCertificateGenerated(ctx context.Context, auth *configloader.ProxyAuthResult, target *connectTarget, cacheHit bool) {
	if auth == nil || auth.WorkspaceID == "" || !shouldEmitProxyEvent(auth.ProxyConfig, "https_proxy.certificate.generated") {
		return
	}
	event := &events.HTTPSProxyCertificateGenerated{
		EventBase: events.NewBase("https_proxy.certificate.generated", events.SeverityInfo, auth.WorkspaceID, reqctx.GetRequestID(ctx)),
		Target:    target.Authority,
		CacheHit:  cacheHit,
		Generated: !cacheHit,
	}
	event.Origin.OriginID = auth.OriginID
	event.Origin.WorkspaceID = auth.WorkspaceID
	events.Emit(ctx, auth.WorkspaceID, event)
}

func (e *Engine) emitDestinationBlocked(ctx context.Context, auth *configloader.ProxyAuthResult, target *connectTarget, reason string) {
	if auth == nil || auth.WorkspaceID == "" || !shouldEmitProxyEvent(auth.ProxyConfig, "https_proxy.destination.blocked") {
		return
	}
	event := &events.HTTPSProxyDestinationBlocked{
		EventBase: events.NewBase("https_proxy.destination.blocked", events.SeverityWarning, auth.WorkspaceID, reqctx.GetRequestID(ctx)),
		Target:    target.Authority,
		Reason:    reason,
	}
	event.Origin.OriginID = auth.OriginID
	event.Origin.WorkspaceID = auth.WorkspaceID
	events.Emit(ctx, auth.WorkspaceID, event)
}

func shouldEmitProxyEvent(cfg *config.Config, eventType string) bool {
	if cfg == nil {
		return false
	}
	return cfg.EventEnabled(eventType)
}

func setProxyMetadata(ctx context.Context, target *connectTarget, mode string, resolvedAddr string) {
	requestData := reqctx.GetRequestData(ctx)
	if requestData == nil {
		return
	}
	if requestData.Data == nil {
		requestData.Data = make(map[string]any)
	}
	requestData.Data["proxy_target_authority"] = target.Authority
	requestData.Data["proxy_target_hostname"] = target.Hostname
	requestData.Data["proxy_target_port"] = target.Port
	requestData.Data["proxy_target_mode"] = mode
	if resolvedAddr != "" {
		requestData.Data["proxy_resolved_addr"] = resolvedAddr
	}
}

func setAIProxyRerouteMetadata(ctx context.Context, originID string) {
	requestData := reqctx.GetRequestData(ctx)
	if requestData == nil {
		return
	}
	if requestData.Data == nil {
		requestData.Data = make(map[string]any)
	}
	requestData.Data["proxy_ai_reroute_origin_id"] = originID
}

func populateAIUsageFromBody(requestData *reqctx.RequestData, trackingWriter *responseTrackingWriter) {
	if requestData == nil || requestData.AIUsage == nil || trackingWriter == nil {
		return
	}
	if requestData.AIUsage.InputTokens > 0 || requestData.AIUsage.OutputTokens > 0 || requestData.AIUsage.TotalTokens > 0 {
		return
	}
	contentType := strings.ToLower(trackingWriter.Header().Get("Content-Type"))
	if !strings.Contains(contentType, "json") {
		return
	}
	body := trackingWriter.BodyBytes()
	if len(body) == 0 {
		return
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return
	}
	if model, ok := raw["model"].(string); ok && requestData.AIUsage.Model == "" {
		requestData.AIUsage.Model = model
	}

	if usageVal, ok := raw["usage"]; ok {
		if usageMap, ok := usageVal.(map[string]any); ok {
			prompt := intFromAny(usageMap["prompt_tokens"])
			completion := intFromAny(usageMap["completion_tokens"])
			total := intFromAny(usageMap["total_tokens"])
			if prompt == 0 {
				prompt = intFromAny(usageMap["input_tokens"])
			}
			if completion == 0 {
				completion = intFromAny(usageMap["output_tokens"])
			}
			if total == 0 {
				total = prompt + completion
			}
			requestData.AIUsage.InputTokens = prompt
			requestData.AIUsage.OutputTokens = completion
			requestData.AIUsage.TotalTokens = total
			return
		}
	}

	if usageVal, ok := raw["usageMetadata"]; ok {
		if usageMap, ok := usageVal.(map[string]any); ok {
			prompt := intFromAny(usageMap["promptTokenCount"])
			completion := intFromAny(usageMap["candidatesTokenCount"])
			total := intFromAny(usageMap["totalTokenCount"])
			if total == 0 {
				total = prompt + completion
			}
			requestData.AIUsage.InputTokens = prompt
			requestData.AIUsage.OutputTokens = completion
			requestData.AIUsage.TotalTokens = total
		}
	}
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}
