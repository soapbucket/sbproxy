package tlsutil

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// --- GetTLSVersion ---

func TestGetTLSVersion_TLS13(t *testing.T) {
	v := GetTLSVersion(13)
	if v != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3 (%#x), got %#x", tls.VersionTLS13, v)
	}
}

func TestGetTLSVersion_TLS12(t *testing.T) {
	v := GetTLSVersion(12)
	if v != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2 (%#x), got %#x", tls.VersionTLS12, v)
	}
}

func TestGetTLSVersion_Zero_DefaultsTLS13(t *testing.T) {
	v := GetTLSVersion(0)
	if v != tls.VersionTLS13 {
		t.Fatalf("expected default TLS 1.3 (%#x), got %#x", tls.VersionTLS13, v)
	}
}

func TestGetTLSVersion_Invalid(t *testing.T) {
	tests := []struct {
		name string
		val  int
	}{
		{"negative", -1},
		{"large", 99},
		{"tls10", 10},
		{"tls11", 11},
		{"tls14", 14},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := GetTLSVersion(tt.val)
			if v != tls.VersionTLS13 {
				t.Fatalf("expected default TLS 1.3 for invalid input %d, got %#x", tt.val, v)
			}
		})
	}
}

// --- GetTLSCiphersFromNames ---

func TestGetTLSCiphersFromNames_Empty(t *testing.T) {
	ciphers := GetTLSCiphersFromNames(nil)
	if len(ciphers) != 0 {
		t.Fatalf("expected 0 ciphers for nil input, got %d", len(ciphers))
	}
	ciphers = GetTLSCiphersFromNames([]string{})
	if len(ciphers) != 0 {
		t.Fatalf("expected 0 ciphers for empty input, got %d", len(ciphers))
	}
}

func TestGetTLSCiphersFromNames_ValidCiphers(t *testing.T) {
	// Pick a cipher that exists in the standard library.
	suites := tls.CipherSuites()
	if len(suites) == 0 {
		t.Skip("no cipher suites available")
	}
	first := suites[0]
	ciphers := GetTLSCiphersFromNames([]string{first.Name})
	if len(ciphers) != 1 {
		t.Fatalf("expected 1 cipher, got %d", len(ciphers))
	}
	if ciphers[0] != first.ID {
		t.Fatalf("expected cipher ID %#x, got %#x", first.ID, ciphers[0])
	}
}

func TestGetTLSCiphersFromNames_MultipleCiphers(t *testing.T) {
	suites := tls.CipherSuites()
	if len(suites) < 2 {
		t.Skip("need at least 2 cipher suites")
	}
	names := []string{suites[0].Name, suites[1].Name}
	ciphers := GetTLSCiphersFromNames(names)
	if len(ciphers) != 2 {
		t.Fatalf("expected 2 ciphers, got %d", len(ciphers))
	}
}

func TestGetTLSCiphersFromNames_InvalidNames(t *testing.T) {
	ciphers := GetTLSCiphersFromNames([]string{"FAKE_CIPHER", "ALSO_FAKE"})
	if len(ciphers) != 0 {
		t.Fatalf("expected 0 ciphers for invalid names, got %d", len(ciphers))
	}
}

func TestGetTLSCiphersFromNames_MixedValidInvalid(t *testing.T) {
	suites := tls.CipherSuites()
	if len(suites) == 0 {
		t.Skip("no cipher suites available")
	}
	names := []string{suites[0].Name, "NONEXISTENT"}
	ciphers := GetTLSCiphersFromNames(names)
	if len(ciphers) != 1 {
		t.Fatalf("expected 1 cipher, got %d", len(ciphers))
	}
}

func TestGetTLSCiphersFromNames_Duplicates(t *testing.T) {
	suites := tls.CipherSuites()
	if len(suites) == 0 {
		t.Skip("no cipher suites available")
	}
	name := suites[0].Name
	ciphers := GetTLSCiphersFromNames([]string{name, name})
	// slices.CompactFunc deduplicates adjacent equal entries, so we expect 1.
	if len(ciphers) != 1 {
		t.Fatalf("expected 1 cipher after dedup, got %d", len(ciphers))
	}
}

func TestGetTLSCiphersFromNames_WhitespaceHandling(t *testing.T) {
	suites := tls.CipherSuites()
	if len(suites) == 0 {
		t.Skip("no cipher suites available")
	}
	// Name with leading/trailing spaces should still match.
	padded := "  " + suites[0].Name + "  "
	ciphers := GetTLSCiphersFromNames([]string{padded})
	if len(ciphers) != 1 {
		t.Fatalf("expected 1 cipher with trimmed name, got %d", len(ciphers))
	}
}

// --- ConnectionTiming ---

func TestNewConnectionTiming(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ct := NewConnectionTiming(client)
	if ct == nil {
		t.Fatal("NewConnectionTiming returned nil")
	}
	if ct.ConnectedAt.IsZero() {
		t.Fatal("ConnectedAt should not be zero")
	}
	if !ct.FirstByteAt.IsZero() {
		t.Fatal("FirstByteAt should be zero before any read")
	}
}

func TestConnectionTiming_DurationBeforeRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ct := NewConnectionTiming(client)
	if d := ct.Duration(); d != 0 {
		t.Fatalf("expected duration 0 before first read, got %v", d)
	}
}

func TestConnectionTiming_ReadSetsFirstByte(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ct := NewConnectionTiming(client)

	// Write some data from the server side.
	go func() {
		server.Write([]byte("hello"))
	}()

	buf := make([]byte, 5)
	n, err := ct.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes, got %d", n)
	}
	if ct.FirstByteAt.IsZero() {
		t.Fatal("FirstByteAt should be set after first read")
	}
	if d := ct.Duration(); d <= 0 {
		// Duration could be 0 if things happen very fast, so just check non-negative.
		// Actually, since ConnectedAt is set before FirstByteAt, duration should be >= 0.
		if d < 0 {
			t.Fatalf("expected non-negative duration, got %v", d)
		}
	}
}

func TestConnectionTiming_SecondReadDoesNotResetFirstByte(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ct := NewConnectionTiming(client)

	go func() {
		server.Write([]byte("ab"))
	}()

	buf := make([]byte, 1)
	ct.Read(buf)
	firstByte := ct.FirstByteAt

	// Small delay to ensure time progresses.
	time.Sleep(1 * time.Millisecond)

	ct.Read(buf)
	if !ct.FirstByteAt.Equal(firstByte) {
		t.Fatal("FirstByteAt should not change on subsequent reads")
	}
}

// --- QUICConnectionTiming ---

func TestNewQUICConnectionTiming(t *testing.T) {
	q := NewQUICConnectionTiming()
	if q == nil {
		t.Fatal("NewQUICConnectionTiming returned nil")
	}
	if q.ConnectedAt.IsZero() {
		t.Fatal("ConnectedAt should not be zero")
	}
	if !q.FirstByteAt.IsZero() {
		t.Fatal("FirstByteAt should be zero initially")
	}
}

func TestQUICConnectionTiming_DurationBeforeFirstByte(t *testing.T) {
	q := NewQUICConnectionTiming()
	if d := q.Duration(); d != 0 {
		t.Fatalf("expected 0 duration before first byte, got %v", d)
	}
}

func TestQUICConnectionTiming_MarkFirstByte(t *testing.T) {
	q := NewQUICConnectionTiming()
	q.MarkFirstByte()
	if q.GetFirstByteAt().IsZero() {
		t.Fatal("FirstByteAt should be set after MarkFirstByte")
	}
}

func TestQUICConnectionTiming_MarkFirstByteIdempotent(t *testing.T) {
	q := NewQUICConnectionTiming()
	q.MarkFirstByte()
	first := q.GetFirstByteAt()

	time.Sleep(1 * time.Millisecond)
	q.MarkFirstByte()

	if !q.GetFirstByteAt().Equal(first) {
		t.Fatal("MarkFirstByte should not update after first call")
	}
}

func TestQUICConnectionTiming_DurationAfterFirstByte(t *testing.T) {
	q := NewQUICConnectionTiming()
	time.Sleep(1 * time.Millisecond)
	q.MarkFirstByte()
	d := q.Duration()
	if d <= 0 {
		t.Fatalf("expected positive duration after marking first byte, got %v", d)
	}
}

func TestQUICConnectionTiming_GetConnectedAt(t *testing.T) {
	before := time.Now()
	q := NewQUICConnectionTiming()
	after := time.Now()

	connAt := q.GetConnectedAt()
	if connAt.Before(before) || connAt.After(after) {
		t.Fatalf("ConnectedAt %v should be between %v and %v", connAt, before, after)
	}
}

// --- CertManager ---

func TestNewCertManager_Empty(t *testing.T) {
	cm, err := NewCertManager(nil, "/tmp", "test")
	if err != nil {
		t.Fatalf("NewCertManager error: %v", err)
	}
	if cm == nil {
		t.Fatal("NewCertManager returned nil")
	}
}

func TestNewCertManager_KeyPairMapping(t *testing.T) {
	pairs := []TLSKeyPair{
		{Cert: "/tmp/cert0.pem", Key: "/tmp/key0.pem"},
		{Cert: "/tmp/cert1.pem", Key: "/tmp/key1.pem"},
	}
	cm, err := NewCertManager(pairs, "/tmp", "test")
	if err != nil {
		t.Fatalf("NewCertManager error: %v", err)
	}
	// First pair should map to "default".
	if _, ok := cm.keyPairs[DefaultTLSKeyPairID]; !ok {
		t.Fatal("first key pair should be stored as default")
	}
	// Second pair should map to "keypair_1".
	if _, ok := cm.keyPairs["keypair_1"]; !ok {
		t.Fatal("second key pair should be stored as keypair_1")
	}
}

func TestCertManager_GetCertificateFunc_MissingKeyPair(t *testing.T) {
	cm, _ := NewCertManager(nil, "/tmp", "test")
	fn := cm.GetCertificateFunc("nonexistent")
	_, err := fn(&tls.ClientHelloInfo{})
	if err == nil {
		t.Fatal("expected error for missing key pair")
	}
}

// --- TimingListener ---

func TestNewTimingListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	tl := NewTimingListener(ln)
	if tl == nil {
		t.Fatal("NewTimingListener returned nil")
	}
	if tl.Addr() == nil {
		t.Fatal("Addr should not be nil")
	}
}

func TestTimingListener_AcceptWrapsConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	tl := NewTimingListener(ln)

	// Connect from client side.
	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			conn.Write([]byte("hi"))
			conn.Close()
		}
	}()

	conn, err := tl.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	defer conn.Close()

	ct, ok := conn.(*ConnectionTiming)
	if !ok {
		t.Fatal("expected accepted connection to be *ConnectionTiming")
	}
	if ct.ConnectedAt.IsZero() {
		t.Fatal("ConnectedAt should be set on accepted connection")
	}
}

func TestTimingListener_Close(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	tl := NewTimingListener(ln)
	if err := tl.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	// Accept after close should fail.
	_, err = tl.Accept()
	if err == nil {
		t.Fatal("expected error on Accept after Close")
	}
}

// --- DefaultTLSKeyPairID ---

func TestDefaultTLSKeyPairID(t *testing.T) {
	if DefaultTLSKeyPairID != "default" {
		t.Fatalf("expected 'default', got %q", DefaultTLSKeyPairID)
	}
}
