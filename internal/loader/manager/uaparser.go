// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/uaparser"
)

// GetUserAgent parses the user agent string from the request
func (m *managerImpl) GetUserAgent(req *http.Request) (*uaparser.Result, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}

	userAgent := req.UserAgent()
	if strings.TrimSpace(userAgent) == "" {
		slog.Debug("empty user agent")
		return nil, nil
	}

	slog.Debug("getting user agent", "user_agent", userAgent)

	if m.uaparser == nil {
		slog.Debug("uaparser manager not initialized")
		return nil, nil
	}

	result, err := m.uaparser.Parse(userAgent)
	if err != nil {
		slog.Error("failed to parse user agent", "user_agent", userAgent, "error", err)
		return nil, err
	}

	slog.Debug("user agent parsed", "result", result)
	return result, nil
}
