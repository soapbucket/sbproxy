package service

import (
	"net"
	"testing"

	proxyproto "github.com/pires/go-proxyproto"
)

func TestProxyProtocolListener_ExtractsClientIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wrapped := newProxyProtocolListener(ln, nil)

	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		header := &proxyproto.Header{
			Version:           1,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("203.0.113.50"), Port: 12345},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080},
		}
		header.WriteTo(conn)
		conn.Write([]byte("hello"))
	}()

	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if host != "203.0.113.50" {
		t.Errorf("expected remote addr 203.0.113.50, got %s", host)
	}
}

func TestProxyProtocolListener_TrustedCIDRs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Only trust 10.0.0.0/8 - 127.0.0.1 is NOT trusted
	wrapped := newProxyProtocolListener(ln, []string{"10.0.0.0/8"})

	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		header := &proxyproto.Header{
			Version:           1,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("203.0.113.50"), Port: 12345},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080},
		}
		header.WriteTo(conn)
		conn.Write([]byte("hello"))
	}()

	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 127.0.0.1 is NOT in trusted CIDRs, so PROXY header should be ignored
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if host == "203.0.113.50" {
		t.Error("untrusted source should not have PROXY header applied")
	}
}
