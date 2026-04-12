// Package proxy implements the streaming reverse proxy handler and its support types.
package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

// ProxyStatusConfig controls RFC 9209 Proxy-Status header generation.
// This is a proxy-local mirror of the config.ProxyStatusConfig type to avoid
// importing internal/config.
type ProxyStatusConfig struct {
	Enable    bool
	ProxyName string
}

// ProxyStatusError represents a structured error for RFC 9209 Proxy-Status.
type ProxyStatusError struct {
	ProxyName string
	ErrorType string // e.g., "destination_not_found", "connection_timeout", "tls_certificate_error"
	Detail    string
}

// ApplyProxyStatusHeader adds the Proxy-Status header per RFC 9209.
func ApplyProxyStatusHeader(resp *http.Response, cfg *ProxyStatusConfig) {
	if cfg == nil || !cfg.Enable {
		return
	}

	proxyName := cfg.ProxyName
	if proxyName == "" {
		proxyName = "soapbucket"
	}

	resp.Header.Set("Proxy-Status", proxyName)
}

// ApplyProxyStatusErrorHeader adds a Proxy-Status header with error details per RFC 9209.
func ApplyProxyStatusErrorHeader(w http.ResponseWriter, pse *ProxyStatusError) {
	if pse == nil {
		return
	}

	proxyName := pse.ProxyName
	if proxyName == "" {
		proxyName = "soapbucket"
	}

	var b strings.Builder
	b.Grow(64)
	b.WriteString(proxyName)

	if pse.ErrorType != "" {
		fmt.Fprintf(&b, "; error=%s", pse.ErrorType)
	}

	if pse.Detail != "" {
		fmt.Fprintf(&b, `; details="%s"`, escapeProxyStatusQuotedString(pse.Detail))
	}

	w.Header().Set("Proxy-Status", b.String())
}

// ClassifyProxyError maps an error string to an RFC 9209 error type.
func ClassifyProxyError(errStr string) string {
	switch {
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline"):
		return "connection_timeout"
	case strings.Contains(errStr, "refused"):
		return "connection_refused"
	case strings.Contains(errStr, "connection") || strings.Contains(errStr, "reset"):
		return "connection_terminated"
	case strings.Contains(errStr, "certificate") || strings.Contains(errStr, "TLS"):
		return "tls_certificate_error"
	case strings.Contains(errStr, "DNS") || strings.Contains(errStr, "no such host"):
		return "dns_error"
	case strings.Contains(errStr, "no route"):
		return "destination_not_found"
	default:
		return "proxy_internal_error"
	}
}

func escapeProxyStatusQuotedString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
