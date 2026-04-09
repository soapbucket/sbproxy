// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"log/slog"
	"net/http"
	"strings"
)

// CSPReportHandler handles CSP violation reports
func CSPReportHandler(c *Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this is a CSP violation report request
			// Look through all security header policies for CSP report URIs
			for _, policy := range c.policies {
				if securityPolicy, ok := policy.(*SecurityHeadersPolicyConfig); ok {
					if securityPolicy.ContentSecurityPolicy != nil &&
						securityPolicy.ContentSecurityPolicy.Enabled &&
						securityPolicy.ContentSecurityPolicy.ReportURI != "" {
						
						reportURI := securityPolicy.ContentSecurityPolicy.ReportURI
						// Remove leading slash for comparison
						reportURI = strings.TrimPrefix(reportURI, "/")
						requestPath := strings.TrimPrefix(r.URL.Path, "/")
						
						// Check if this request matches the report URI
						if requestPath == reportURI || strings.HasPrefix(requestPath, reportURI) {
							slog.Debug("CSP violation report endpoint matched",
								"path", r.URL.Path,
								"report_uri", reportURI,
								"config_id", c.ID,
								"method", r.Method)
							
							handler := NewCSPViolationReportHandler(c)
							handler.ServeHTTP(w, r)
							return
						}
					}
				}
			}

			// Not a CSP report request, continue to next handler
			next.ServeHTTP(w, r)
		})
	}
}

