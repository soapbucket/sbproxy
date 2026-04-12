package lua

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestRequestIPVariable(t *testing.T) {
	tests := []struct {
		name   string
		setup  func() *http.Request
		script string
		want   bool
	}{
		{
			name: "request_ip from X-Real-IP",
			setup: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-Real-IP", "203.0.113.1")
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			script: `
function match_request(req, ctx)
	return ctx.request_ip == "203.0.113.1"
end
			`,
			want: true,
		},
		{
			name: "request_ip from X-Forwarded-For",
			setup: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-Forwarded-For", "203.0.113.2, 192.168.1.1")
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			script: `
function match_request(req, ctx)
	return ctx.request_ip == "203.0.113.2"
end
			`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setup()
			matcher, err := NewMatcher(tt.script)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPFunctions(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		{"ip.is_private", `function match_request(req, ctx)
return ctx.ip.is_private("192.168.1.1")
end`, true},
		{"not private", `function match_request(req, ctx)
return not ctx.ip.is_private("8.8.8.8")
end`, true},
		{"ip.is_ipv4", `function match_request(req, ctx)
return ctx.ip.is_ipv4("192.168.1.1")
end`, true},
		{"ip.is_ipv6", `function match_request(req, ctx)
return ctx.ip.is_ipv6("2001:db8::1")
end`, true},
		{"ip.is_loopback", `function match_request(req, ctx)
return ctx.ip.is_loopback("127.0.0.1")
end`, true},
		{"ip.in_cidr", `function match_request(req, ctx)
return ctx.ip.in_cidr("192.168.1.100", "192.168.1.0/24")
end`, true},
		{"ip.compare equal", `function match_request(req, ctx)
return ctx.ip.compare("192.168.1.1", "192.168.1.1") == 0
end`, true},
		{"ip.compare less", `function match_request(req, ctx)
return ctx.ip.compare("192.168.1.1", "192.168.1.2") < 0
end`, true},
		{"ip.parse", `function match_request(req, ctx)
local info = ctx.ip.parse("192.168.1.1")
return info.is_private and info.is_ipv4
end`, true},
		{"ip.in_range", `function match_request(req, ctx)
return ctx.ip.in_range("192.168.1.100", "192.168.1.1", "192.168.1.255")
end`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			matcher, err := NewMatcher(tt.script)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPModifier(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.1.50")

	script := `
function modify_request(req, ctx)
	return {
		add_headers = {
			["X-Client-IP"] = ctx.request_ip,
			["X-IP-Type"] = ctx.ip.is_private(ctx.request_ip) and "private" or "public"
		}
	}
end
	`

	modifier, err := NewModifier(script)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if got := modifiedReq.Header.Get("X-Client-IP"); got != "10.0.1.50" {
		t.Errorf("X-Client-IP = %v, want 10.0.1.50", got)
	}

	if got := modifiedReq.Header.Get("X-IP-Type"); got != "private" {
		t.Errorf("X-IP-Type = %v, want private", got)
	}
}

func TestVariablesInLuaContext(t *testing.T) {
	tests := []struct {
		name      string
		variables map[string]any
		script    string
		want      bool
	}{
		{
			name: "access string variable",
			variables: map[string]any{
				"api_url": "https://api.example.com",
			},
			script: `
function match_request(req, ctx)
	return ctx.variables.api_url == "https://api.example.com"
end
			`,
			want: true,
		},
		{
			name: "access nested variable",
			variables: map[string]any{
				"endpoints": map[string]any{
					"users": "/api/v2/users",
				},
			},
			script: `
function match_request(req, ctx)
	return ctx.variables.endpoints.users == "/api/v2/users"
end
			`,
			want: true,
		},
		{
			name: "access numeric variable",
			variables: map[string]any{
				"max_retries": float64(3),
			},
			script: `
function match_request(req, ctx)
	return ctx.variables.max_retries == 3
end
			`,
			want: true,
		},
		{
			name:      "nil variables returns empty table",
			variables: nil,
			script: `
function match_request(req, ctx)
	return type(ctx.variables) == "table"
end
			`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rd := &reqctx.RequestData{
				ID:           "test-id",
				DebugHeaders: make(map[string]string),
				Data:         make(map[string]any),
				Variables:    tt.variables,
			}
			ctx := reqctx.SetRequestData(req.Context(), rd)
			req = req.WithContext(ctx)

			matcher, err := NewMatcher(tt.script)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}
