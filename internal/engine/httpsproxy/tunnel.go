package httpsproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
)

// TunnelTransport identifies how a client tunnel was established.
type TunnelTransport string

const (
	// TunnelTransportClassicConnect represents classic HTTP/1.1 CONNECT via Hijack.
	TunnelTransportClassicConnect TunnelTransport = "classic_connect"
	// TunnelTransportExtendedConnectHTTP2 represents future HTTP/2 extended CONNECT support.
	TunnelTransportExtendedConnectHTTP2 TunnelTransport = "extended_connect_http2"
	// TunnelTransportExtendedConnectHTTP3 represents future HTTP/3 extended CONNECT support.
	TunnelTransportExtendedConnectHTTP3 TunnelTransport = "extended_connect_http3"
)

// EstablishedTunnel represents a bidirectional tunnel endpoint that can back
// classic CONNECT today and stream-backed CONNECT variants later.
type EstablishedTunnel interface {
	io.ReadWriteCloser
	Close() error
	BytesTransferred() int64
	Transport() TunnelTransport
}

// ConnBackedTunnel is an EstablishedTunnel that also exposes a raw net.Conn.
// Managed MITM interception still depends on this today.
type ConnBackedTunnel interface {
	EstablishedTunnel
	NetConn() net.Conn
}

// TunnelEstablisher creates a client tunnel endpoint from an incoming request.
// Future HTTP/2 and HTTP/3 implementations can provide stream-backed versions.
type TunnelEstablisher interface {
	Establish(w http.ResponseWriter, r *http.Request) (EstablishedTunnel, error)
	Transport() TunnelTransport
}

type classicConnectEstablisher struct{}

func (classicConnectEstablisher) Transport() TunnelTransport {
	return TunnelTransportClassicConnect
}

func (classicConnectEstablisher) Establish(w http.ResponseWriter, _ *http.Request) (EstablishedTunnel, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("Hijacking not supported")
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("Failed to hijack connection")
	}

	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	observed := &observedConn{Conn: conn}
	return &classicEstablishedTunnel{conn: observed}, nil
}

type classicEstablishedTunnel struct {
	conn *observedConn
}

func (t *classicEstablishedTunnel) Read(p []byte) (int, error) {
	return t.conn.Read(p)
}

func (t *classicEstablishedTunnel) Write(p []byte) (int, error) {
	return t.conn.Write(p)
}

func (t *classicEstablishedTunnel) NetConn() net.Conn {
	return t.conn
}

func (t *classicEstablishedTunnel) Close() error {
	return t.conn.Close()
}

func (t *classicEstablishedTunnel) BytesTransferred() int64 {
	return t.conn.BytesTransferred()
}

func (t *classicEstablishedTunnel) Transport() TunnelTransport {
	return TunnelTransportClassicConnect
}

type streamConnectEstablisher struct {
	transport TunnelTransport
}

func (s streamConnectEstablisher) Transport() TunnelTransport {
	return s.transport
}

func (s streamConnectEstablisher) Establish(w http.ResponseWriter, r *http.Request) (EstablishedTunnel, error) {
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	return &streamEstablishedTunnel{
		body:       r.Body,
		writer:     w,
		controller: rc,
		transport:  s.transport,
	}, nil
}

type streamEstablishedTunnel struct {
	body       io.ReadCloser
	writer     http.ResponseWriter
	controller *http.ResponseController
	transport  TunnelTransport
	read       atomic.Int64
	written    atomic.Int64
}

func (t *streamEstablishedTunnel) Read(p []byte) (int, error) {
	n, err := t.body.Read(p)
	if n > 0 {
		t.read.Add(int64(n))
	}
	return n, err
}

func (t *streamEstablishedTunnel) Write(p []byte) (int, error) {
	n, err := t.writer.Write(p)
	if n > 0 {
		t.written.Add(int64(n))
	}
	if err == nil && t.controller != nil {
		_ = t.controller.Flush()
	}
	return n, err
}

func (t *streamEstablishedTunnel) Close() error {
	if t.body != nil {
		return t.body.Close()
	}
	return nil
}

func (t *streamEstablishedTunnel) BytesTransferred() int64 {
	return t.read.Load() + t.written.Load()
}

func (t *streamEstablishedTunnel) Transport() TunnelTransport {
	return t.transport
}
