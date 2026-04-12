// client_ip.go extracts the real client IP from X-Forwarded-For, X-Real-IP, or RemoteAddr.
package httpkit

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP extracts the real client IP from a request, checking
// X-Forwarded-For, X-Real-IP, and RemoteAddr in that order.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// SplitHostPort wraps net.SplitHostPort with a fallback that returns
// the input as host if no port is present.
func SplitHostPort(addr string) (host, port string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return h, p
}
