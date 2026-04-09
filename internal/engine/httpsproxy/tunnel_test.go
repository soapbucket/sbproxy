package httpsproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClassicConnectEstablisher_Establish(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	w := &hijackableResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		conn:           serverConn,
	}
	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)

	done := make(chan string, 1)
	go func() {
		defer clientConn.Close()
		_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
		_, _ = io.ReadFull(clientConn, buf)
		done <- string(buf)
	}()

	tunnel, err := classicConnectEstablisher{}.Establish(w, req)
	if err != nil {
		t.Fatalf("expected establish to succeed, got error: %v", err)
	}
	defer tunnel.Close()

	if tunnel.Transport() != TunnelTransportClassicConnect {
		t.Fatalf("expected classic connect transport, got %s", tunnel.Transport())
	}
	if _, ok := tunnel.(ConnBackedTunnel); !ok {
		t.Fatal("expected classic tunnel to expose a net.Conn")
	}

	select {
	case msg := <-done:
		if msg != "HTTP/1.1 200 Connection Established\r\n\r\n" {
			t.Fatalf("unexpected CONNECT acknowledgement: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CONNECT acknowledgement")
	}
}

func TestEngineSelectTunnelEstablisherDefaultsToClassic(t *testing.T) {
	engine := &Engine{}
	establisher := engine.selectTunnelEstablisher(httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil))
	if establisher.Transport() != TunnelTransportClassicConnect {
		t.Fatalf("expected classic establish transport, got %s", establisher.Transport())
	}
}

func TestEngineSelectTunnelEstablisherRejectsHTTP2ExtendedConnect(t *testing.T) {
	engine := &Engine{}
	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
	req.ProtoMajor = 2
	establisher := engine.selectTunnelEstablisher(req)
	if establisher.Transport() != TunnelTransportExtendedConnectHTTP2 {
		t.Fatalf("expected HTTP/2 extended CONNECT transport, got %s", establisher.Transport())
	}
	rec := httptest.NewRecorder()
	tunnel, err := establisher.Establish(rec, req)
	if err != nil {
		t.Fatalf("expected stream establisher to succeed, got error: %v", err)
	}
	defer tunnel.Close()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 status for stream CONNECT establish, got %d", rec.Code)
	}
}

func TestEngineSelectTunnelEstablisherRejectsHTTP3ExtendedConnect(t *testing.T) {
	engine := &Engine{}
	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
	req.ProtoMajor = 3
	establisher := engine.selectTunnelEstablisher(req)
	if establisher.Transport() != TunnelTransportExtendedConnectHTTP3 {
		t.Fatalf("expected HTTP/3 extended CONNECT transport, got %s", establisher.Transport())
	}
	rec := httptest.NewRecorder()
	tunnel, err := establisher.Establish(rec, req)
	if err != nil {
		t.Fatalf("expected stream establisher to succeed, got error: %v", err)
	}
	defer tunnel.Close()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 status for stream CONNECT establish, got %d", rec.Code)
	}
}

func TestStreamConnectEstablisher_ReadWrite(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", io.NopCloser(strings.NewReader("ping")))
	req.ProtoMajor = 2
	rec := httptest.NewRecorder()

	tunnel, err := streamConnectEstablisher{transport: TunnelTransportExtendedConnectHTTP2}.Establish(rec, req)
	if err != nil {
		t.Fatalf("expected establish to succeed, got error: %v", err)
	}
	defer tunnel.Close()

	buf := make([]byte, 4)
	n, err := tunnel.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected read error: %v", err)
	}
	if got := string(buf[:n]); got != "ping" {
		t.Fatalf("expected to read ping, got %q", got)
	}

	if _, err := tunnel.Write([]byte("pong")); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if got := rec.Body.String(); got != "pong" {
		t.Fatalf("expected response body pong, got %q", got)
	}
	if tunnel.BytesTransferred() < 8 {
		t.Fatalf("expected bytes transferred to be tracked, got %d", tunnel.BytesTransferred())
	}
}

type hijackableResponseWriter struct {
	http.ResponseWriter
	conn net.Conn
}

func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn))
	return w.conn, rw, nil
}
