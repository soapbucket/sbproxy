package rule

import (
	"net/http"
	"testing"
)

func TestProtoVersionMatching(t *testing.T) {
	tests := []struct {
		name     string
		rule     RequestRule
		req      *http.Request
		expected bool
	}{
		// Single version matching
		{
			name: "HTTP/1.0 version matches",
			rule: RequestRule{
				ProtoVersion: "1.0",
			},
			req:      createHTTP10Request(t),
			expected: true,
		},
		{
			name: "HTTP/1.1 version matches",
			rule: RequestRule{
				ProtoVersion: "1.1",
			},
			req:      createHTTP1Request(t),
			expected: true,
		},
		{
			name: "HTTP/2.0 version matches",
			rule: RequestRule{
				ProtoVersion: "2.0",
			},
			req:      createHTTP2Request(t),
			expected: true,
		},
		{
			name: "HTTP/3.0 version matches",
			rule: RequestRule{
				ProtoVersion: "3.0",
			},
			req:      createHTTP3Request(t),
			expected: true,
		},
		{
			name: "HTTP/1.1 version does not match HTTP/2.0",
			rule: RequestRule{
				ProtoVersion: "1.1",
			},
			req:      createHTTP2Request(t),
			expected: false,
		},
		{
			name: "HTTP/2.0 version does not match HTTP/1.1",
			rule: RequestRule{
				ProtoVersion: "2.0",
			},
			req:      createHTTP1Request(t),
			expected: false,
		},

		// Multiple versions matching
		{
			name: "ProtoVersions - one matches",
			rule: RequestRule{
				ProtoVersions: []string{"1.0", "1.1"},
			},
			req:      createHTTP1Request(t),
			expected: true,
		},
		{
			name: "ProtoVersions - different one matches",
			rule: RequestRule{
				ProtoVersions: []string{"1.1", "2.0"},
			},
			req:      createHTTP2Request(t),
			expected: true,
		},
		{
			name: "ProtoVersions - none match",
			rule: RequestRule{
				ProtoVersions: []string{"1.0", "1.1"},
			},
			req:      createHTTP2Request(t),
			expected: false,
		},
		{
			name: "ProtoVersions - includes 3.0",
			rule: RequestRule{
				ProtoVersions: []string{"2.0", "3.0"},
			},
			req:      createHTTP3Request(t),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Match(tt.req)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestProtocolMatching(t *testing.T) {
	tests := []struct {
		name     string
		rule     RequestRule
		req      *http.Request
		expected bool
	}{
		// Single protocol matching
		{
			name: "HTTP/1.1 matches",
			rule: RequestRule{
				Protocol: "http1",
			},
			req:      createHTTP1Request(t),
			expected: true,
		},
		{
			name: "HTTP/2 matches",
			rule: RequestRule{
				Protocol: "http2",
			},
			req:      createHTTP2Request(t),
			expected: true,
		},
		{
			name: "HTTP/3 matches",
			rule: RequestRule{
				Protocol: "http3",
			},
			req:      createHTTP3Request(t),
			expected: true,
		},
		{
			name: "WebSocket matches",
			rule: RequestRule{
				Protocol: "websocket",
			},
			req:      createWebSocketRequest(t),
			expected: true,
		},
		{
			name: "gRPC matches",
			rule: RequestRule{
				Protocol: "grpc",
			},
			req:      createGRPCRequest(t),
			expected: true,
		},
		{
			name: "HTTP/2 bidirectional matches",
			rule: RequestRule{
				Protocol: "http2_bidirectional",
			},
			req:      createHTTP2BidirectionalRequest(t),
			expected: true,
		},
		{
			name: "Generic HTTP matches HTTP/1.1",
			rule: RequestRule{
				Protocol: "http",
			},
			req:      createHTTP1Request(t),
			expected: true,
		},
		{
			name: "Generic HTTP matches HTTP/2",
			rule: RequestRule{
				Protocol: "http",
			},
			req:      createHTTP2Request(t),
			expected: true,
		},
		{
			name: "Generic HTTP matches HTTP/3",
			rule: RequestRule{
				Protocol: "http",
			},
			req:      createHTTP3Request(t),
			expected: true,
		},
		{
			name: "Generic HTTP does not match WebSocket",
			rule: RequestRule{
				Protocol: "http",
			},
			req:      createWebSocketRequest(t),
			expected: false,
		},
		{
			name: "HTTP/1.1 does not match HTTP/2",
			rule: RequestRule{
				Protocol: "http1",
			},
			req:      createHTTP2Request(t),
			expected: false,
		},
		{
			name: "WebSocket does not match HTTP/1.1",
			rule: RequestRule{
				Protocol: "websocket",
			},
			req:      createHTTP1Request(t),
			expected: false,
		},

		// Multiple protocols matching
		{
			name: "Protocols - one matches",
			rule: RequestRule{
				Protocols: []string{"http1", "http2"},
			},
			req:      createHTTP1Request(t),
			expected: true,
		},
		{
			name: "Protocols - different one matches",
			rule: RequestRule{
				Protocols: []string{"http1", "http2"},
			},
			req:      createHTTP2Request(t),
			expected: true,
		},
		{
			name: "Protocols - none match",
			rule: RequestRule{
				Protocols: []string{"http1", "http2"},
			},
			req:      createWebSocketRequest(t),
			expected: false,
		},
		{
			name: "Protocols - includes generic http",
			rule: RequestRule{
				Protocols: []string{"http", "websocket"},
			},
			req:      createHTTP3Request(t),
			expected: true,
		},
		{
			name: "Protocols - includes gRPC",
			rule: RequestRule{
				Protocols: []string{"http1", "grpc"},
			},
			req:      createGRPCRequest(t),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Match(tt.req)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func createHTTP10Request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.ProtoMajor = 1
	req.ProtoMinor = 0
	return req
}

func createHTTP1Request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	return req
}

func createHTTP2Request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	return req
}

func createHTTP3Request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.ProtoMajor = 3
	req.ProtoMinor = 0
	return req
}

func createWebSocketRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	return req
}

func createGRPCRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.ProtoMajor = 2
	req.Header.Set("Content-Type", "application/grpc")
	return req
}

func createHTTP2BidirectionalRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.ProtoMajor = 2
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/x-ndjson")
	return req
}
