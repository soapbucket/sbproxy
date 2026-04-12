// ip_mask.go provides IP address anonymization via truncation or hashing.
package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
)

// maskIP anonymizes an IP address based on the configured mode.
func maskIP(ip string, mode string) string {
	switch mode {
	case "truncate":
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return ip
		}
		if v4 := parsed.To4(); v4 != nil {
			v4[3] = 0
			return v4.String()
		}
		// IPv6: zero last 80 bits (last 10 bytes)
		for i := 6; i < 16; i++ {
			parsed[i] = 0
		}
		return parsed.String()
	case "hash":
		h := sha256.Sum256([]byte(ip))
		return hex.EncodeToString(h[:8])
	default:
		return ip
	}
}

// ipMaskMode returns the masking mode from config, or "" if masking is disabled.
func ipMaskMode(cfg *RequestLoggingConfig) string {
	if cfg == nil || cfg.IPMasking == nil {
		return ""
	}
	return cfg.IPMasking.Mode
}
