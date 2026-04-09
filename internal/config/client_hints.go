// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
	"strings"
)

// standardClientHints lists the well-known client hint headers from RFC 8942
// and related specifications (UA-CH, Device hints, Network hints).
var standardClientHints = map[string]bool{
	"Sec-CH-UA":          true,
	"Sec-CH-UA-Mobile":   true,
	"Sec-CH-UA-Platform": true,
	"DPR":                true,
	"Device-Memory":      true,
	"Viewport-Width":     true,
	"Width":              true,
	"ECT":                true,
	"RTT":                true,
	"Downlink":           true,
	"Save-Data":          true,
}

// ClientHintsConfig configures HTTP Client Hints per RFC 8942.
// When enabled, the proxy injects Accept-CH and Critical-CH headers on responses
// and forwards client hint request headers to upstream origins.
type ClientHintsConfig struct {
	// Enable client hints processing.
	// Default: false
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`

	// AcceptCH lists the client hint headers the server wishes to receive.
	// These are sent in the Accept-CH response header.
	// Example: ["Sec-CH-UA", "Sec-CH-UA-Mobile", "DPR", "Viewport-Width"]
	AcceptCH []string `json:"accept_ch,omitempty" yaml:"accept_ch,omitempty"`

	// CriticalCH lists the client hint headers that are critical for correct
	// content selection. If missing, the client should retry the request.
	// These are sent in the Critical-CH response header.
	CriticalCH []string `json:"critical_ch,omitempty" yaml:"critical_ch,omitempty"`

	// Lifetime specifies the duration (in seconds) for which the client should
	// remember the Accept-CH preference. Sent as Accept-CH-Lifetime header.
	// 0 means omit the header (use browser default behavior).
	Lifetime int `json:"lifetime,omitempty" yaml:"lifetime,omitempty"`
}

// applyClientHintsHeaders injects Accept-CH, Critical-CH, and Accept-CH-Lifetime
// headers on outgoing responses so clients know which hints to send.
func applyClientHintsHeaders(resp *http.Response, cfg *ClientHintsConfig) {
	if cfg == nil || !cfg.Enable {
		return
	}

	if len(cfg.AcceptCH) > 0 {
		resp.Header.Set("Accept-CH", strings.Join(cfg.AcceptCH, ", "))
	}

	if len(cfg.CriticalCH) > 0 {
		resp.Header.Set("Critical-CH", strings.Join(cfg.CriticalCH, ", "))
	}

	if cfg.Lifetime > 0 {
		resp.Header.Set("Accept-CH-Lifetime", formatInt(cfg.Lifetime))
	}
}

// forwardClientHints copies client hint request headers from the original client
// request to the outgoing upstream request. Only headers listed in cfg.AcceptCH
// are forwarded. If AcceptCH is empty, all standard client hint headers are forwarded.
func forwardClientHints(outReq, clientReq *http.Request, cfg *ClientHintsConfig) {
	if cfg == nil || !cfg.Enable {
		return
	}

	if len(cfg.AcceptCH) > 0 {
		for _, hint := range cfg.AcceptCH {
			val := clientReq.Header.Get(hint)
			if val != "" {
				outReq.Header.Set(hint, val)
			}
		}
		return
	}

	// Forward all standard client hints when no explicit list is configured
	for hint := range standardClientHints {
		val := clientReq.Header.Get(hint)
		if val != "" {
			outReq.Header.Set(hint, val)
		}
	}
}

// formatInt converts an integer to its string representation without importing strconv.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
