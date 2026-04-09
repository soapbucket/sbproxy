// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func init() {
	loaderFns[TypeRedirect] = LoadRedirectConfig
}

var _ ActionConfig = (*RedirectTypedConfig)(nil)

// RedirectTypedConfig represents the redirect-specific configuration
type RedirectTypedConfig struct {
	RedirectConfig
}

// LoadRedirectConfig loads a redirect configuration
func LoadRedirectConfig(data []byte) (ActionConfig, error) {
	cfg := new(RedirectTypedConfig)
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Validate status code
	switch cfg.StatusCode {
	case http.StatusMovedPermanently, // 301
		http.StatusFound,             // 302
		http.StatusSeeOther,          // 303
		http.StatusTemporaryRedirect, // 307
		http.StatusPermanentRedirect: // 308
		// Valid
	default:
		return nil, fmt.Errorf("invalid redirect status code: %d", cfg.StatusCode)
	}

	cfg.tr = http.RoundTripper(RedirectTransportFn(&cfg.RedirectConfig))

	return cfg, nil
}

// RedirectTransportFn is a variable for redirect transport fn.
var RedirectTransportFn = func(cfg *RedirectConfig) http.RoundTripper {
	return TransportFn(func(req *http.Request) (*http.Response, error) {
		// Build redirect URL
		redirectURL := cfg.URL

		// Append original path if configured
		if cfg.StripBasePath {
			redirectURL = strings.TrimSuffix(redirectURL, "/") + req.URL.Path
		}

		// Append original query if configured
		if cfg.PreserveQuery && req.URL.RawQuery != "" {
			if strings.Contains(redirectURL, "?") {
				redirectURL += "&" + req.URL.RawQuery
			} else {
				redirectURL += "?" + req.URL.RawQuery
			}
		}

		// Create response
		resp := &http.Response{
			StatusCode: cfg.StatusCode,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}

		// Set Location header
		resp.Header.Set("Location", redirectURL)
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")

		// Add a simple HTML body for browsers that don't follow redirects automatically
		body := buildRedirectBody(redirectURL)
		resp.Body = io.NopCloser(strings.NewReader(body))
		resp.ContentLength = int64(len(body))

		return resp, nil
	})
}

// buildRedirectBody creates a simple HTML page with redirect instructions
func buildRedirectBody(url string) string {
	const template = `<!DOCTYPE html>
<html>
<head>
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=%s">
</head>
<body>
    <p>Redirecting to <a href="%s">%s</a>...</p>
</body>
</html>`
	return strings.ReplaceAll(template, "%s", url)
}
