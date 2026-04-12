package cel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPParse(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "parse IPv4 and check is_ipv4",
			expr:      `ip.parse("192.168.1.1")['is_ipv4'] == true`,
			wantMatch: true,
		},
		{
			name:      "parse IPv6 and check is_ipv6",
			expr:      `ip.parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334")['is_ipv6'] == true`,
			wantMatch: true,
		},
		{
			name:      "parse localhost and check is_loopback",
			expr:      `ip.parse("127.0.0.1")['is_loopback'] == true`,
			wantMatch: true,
		},
		{
			name:      "parse private IP",
			expr:      `ip.parse("192.168.1.1")['is_private'] == true`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestIPInCIDR(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "IP in CIDR range",
			expr:      `ip.inCIDR("192.168.1.100", "192.168.1.0/24")`,
			wantMatch: true,
		},
		{
			name:      "IP not in CIDR range",
			expr:      `ip.inCIDR("192.168.2.100", "192.168.1.0/24")`,
			wantMatch: false,
		},
		{
			name:      "IPv6 in CIDR",
			expr:      `ip.inCIDR("2001:db8::1", "2001:db8::/32")`,
			wantMatch: true,
		},
		{
			name:      "localhost in loopback range",
			expr:      `ip.inCIDR("127.0.0.1", "127.0.0.0/8")`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestIPIsPrivate(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "private 10.x.x.x",
			expr:      `ip.isPrivate("10.0.0.1")`,
			wantMatch: true,
		},
		{
			name:      "private 172.16.x.x",
			expr:      `ip.isPrivate("172.16.0.1")`,
			wantMatch: true,
		},
		{
			name:      "private 192.168.x.x",
			expr:      `ip.isPrivate("192.168.1.1")`,
			wantMatch: true,
		},
		{
			name:      "public IP",
			expr:      `ip.isPrivate("8.8.8.8")`,
			wantMatch: false,
		},
		{
			name:      "loopback is private",
			expr:      `ip.isPrivate("127.0.0.1")`,
			wantMatch: true,
		},
		{
			name:      "link-local is private",
			expr:      `ip.isPrivate("169.254.1.1")`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestIPIsLoopback(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "IPv4 loopback",
			expr:      `ip.isLoopback("127.0.0.1")`,
			wantMatch: true,
		},
		{
			name:      "IPv4 loopback range",
			expr:      `ip.isLoopback("127.0.0.100")`,
			wantMatch: true,
		},
		{
			name:      "IPv6 loopback",
			expr:      `ip.isLoopback("::1")`,
			wantMatch: true,
		},
		{
			name:      "not loopback",
			expr:      `ip.isLoopback("192.168.1.1")`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestIPIsIPv4(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "IPv4 address",
			expr:      `ip.isIPv4("192.168.1.1")`,
			wantMatch: true,
		},
		{
			name:      "IPv6 address",
			expr:      `ip.isIPv4("2001:db8::1")`,
			wantMatch: false,
		},
		{
			name:      "loopback IPv4",
			expr:      `ip.isIPv4("127.0.0.1")`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestIPIsIPv6(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "IPv6 address",
			expr:      `ip.isIPv6("2001:db8::1")`,
			wantMatch: true,
		},
		{
			name:      "IPv4 address",
			expr:      `ip.isIPv6("192.168.1.1")`,
			wantMatch: false,
		},
		{
			name:      "IPv6 loopback",
			expr:      `ip.isIPv6("::1")`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestIPInRange(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "IP in range",
			expr:      `ip.inRange("192.168.1.100", "192.168.1.1", "192.168.1.255")`,
			wantMatch: true,
		},
		{
			name:      "IP at start of range",
			expr:      `ip.inRange("192.168.1.1", "192.168.1.1", "192.168.1.255")`,
			wantMatch: true,
		},
		{
			name:      "IP at end of range",
			expr:      `ip.inRange("192.168.1.255", "192.168.1.1", "192.168.1.255")`,
			wantMatch: true,
		},
		{
			name:      "IP before range",
			expr:      `ip.inRange("192.168.0.255", "192.168.1.1", "192.168.1.255")`,
			wantMatch: false,
		},
		{
			name:      "IP after range",
			expr:      `ip.inRange("192.168.2.1", "192.168.1.1", "192.168.1.255")`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestIPCompare(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "equal IPs",
			expr:      `ip.compare("192.168.1.1", "192.168.1.1") == 0`,
			wantMatch: true,
		},
		{
			name:      "first IP less than second",
			expr:      `ip.compare("192.168.1.1", "192.168.1.2") < 0`,
			wantMatch: true,
		},
		{
			name:      "first IP greater than second",
			expr:      `ip.compare("192.168.1.2", "192.168.1.1") > 0`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestRequestIPVariable(t *testing.T) {
	tests := []struct {
		name        string
		setupReq    func() *http.Request
		expr        string
		wantMatch   bool
		description string
	}{
		{
			name: "client.ip from X-Real-IP",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.Header.Set("X-Real-IP", "203.0.113.1")
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			expr:        `client.ip == "203.0.113.1"`,
			wantMatch:   true,
			description: "Should extract IP from X-Real-IP header",
		},
		{
			name: "client.ip from X-Forwarded-For",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.Header.Set("X-Forwarded-For", "203.0.113.2, 192.168.1.1")
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			expr:        `client.ip == "203.0.113.2"`,
			wantMatch:   true,
			description: "Should extract first IP from X-Forwarded-For",
		},
		{
			name: "client.ip from RemoteAddr",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.RemoteAddr = "192.168.1.100:12345"
				return req
			},
			expr:        `client.ip.startsWith("192.168.1")`,
			wantMatch:   true,
			description: "Should extract IP from RemoteAddr",
		},
		{
			name: "check if client.ip is private",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.RemoteAddr = "192.168.1.100:12345"
				return req
			},
			expr:        `ip.isPrivate(client.ip)`,
			wantMatch:   true,
			description: "Should work with IP functions",
		},
		{
			name: "check if client.ip in CIDR",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.Header.Set("X-Real-IP", "10.0.1.50")
				return req
			},
			expr:        `ip.inCIDR(client.ip, "10.0.0.0/8")`,
			wantMatch:   true,
			description: "Should check CIDR range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v (%s)", got, tt.wantMatch, tt.description)
			}
		})
	}
}

func TestRequestIPInModifier(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Real-IP", "203.0.113.5")

	expr := `{
		"add_headers": {
			"X-Client-IP": client.ip,
			"X-IP-Type": ip.isPrivate(client.ip) ? "private" : "public"
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	clientIP := modifiedReq.Header.Get("X-Client-IP")
	if clientIP != "203.0.113.5" {
		t.Errorf("Expected X-Client-IP = 203.0.113.5, got %s", clientIP)
	}

	ipType := modifiedReq.Header.Get("X-IP-Type")
	if ipType != "public" {
		t.Errorf("Expected X-IP-Type = public, got %s", ipType)
	}
}

func TestRequestIPInResponseModifier(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Real-IP", "10.0.1.100")

	expr := `{
		"add_headers": {
			"X-Request-IP": client.ip,
			"X-IP-Private": ip.isPrivate(client.ip) ? "yes" : "no"
		}
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    req,
	}

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	requestIP := resp.Header.Get("X-Request-IP")
	if requestIP != "10.0.1.100" {
		t.Errorf("Expected X-Request-IP = 10.0.1.100, got %s", requestIP)
	}

	ipPrivate := resp.Header.Get("X-IP-Private")
	if ipPrivate != "yes" {
		t.Errorf("Expected X-IP-Private = yes, got %s", ipPrivate)
	}
}

func TestComplexIPExpressions(t *testing.T) {
	tests := []struct {
		name      string
		setupReq  func() *http.Request
		expr      string
		wantMatch bool
	}{
		{
			name: "multiple IP conditions",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.Header.Set("X-Real-IP", "192.168.1.100")
				return req
			},
			expr:      `ip.isPrivate(client.ip) && ip.inCIDR(client.ip, "192.168.1.0/24") && ip.isIPv4(client.ip)`,
			wantMatch: true,
		},
		{
			name: "IP range check with fallback",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.Header.Set("X-Real-IP", "10.0.0.50")
				return req
			},
			expr:      `ip.inCIDR(client.ip, "10.0.0.0/24") || ip.inCIDR(client.ip, "172.16.0.0/12")`,
			wantMatch: true,
		},
		{
			name: "parse and check IP properties",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.Header.Set("X-Real-IP", "8.8.8.8")
				return req
			},
			expr:      `!ip.isPrivate(client.ip) && ip.isIPv4(client.ip)`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}
