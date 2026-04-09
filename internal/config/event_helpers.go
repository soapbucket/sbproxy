// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func requestEventIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if idx := strings.IndexByte(forwarded, ','); idx >= 0 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return strings.TrimSpace(forwarded)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func emitSecurityAuthFailure(ctx context.Context, cfg *Config, r *http.Request, authType string, reason string) {
	if cfg == nil || !cfg.EventEnabled("security.auth_failure") {
		return
	}
	event := &events.SecurityAuthFailure{
		EventBase: events.NewBase("security.auth_failure", events.SeverityError, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		IP:        requestEventIP(r),
		Path:      requestPath(r),
		AuthType:  authType,
		Reason:    reason,
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func emitSecurityRateLimited(ctx context.Context, cfg *Config, r *http.Request, policyName string, limit int, window string) {
	if cfg == nil || !cfg.EventEnabled("security.rate_limited") {
		return
	}
	event := &events.SecurityRateLimited{
		EventBase:  events.NewBase("security.rate_limited", events.SeverityWarning, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		IP:         requestEventIP(r),
		Path:       requestPath(r),
		PolicyName: policyName,
		Limit:      limit,
		Window:     window,
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func emitSecurityPIIDetected(ctx context.Context, cfg *Config, r *http.Request, entities []string) {
	if cfg == nil || !cfg.EventEnabled("security.pii_detected") {
		return
	}
	event := &events.SecurityPIIDetected{
		EventBase: events.NewBase("security.pii_detected", events.SeverityWarning, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		IP:        requestEventIP(r),
		Path:      requestPath(r),
		Entities:  entities,
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func emitWebSocketConnectionLifecycle(ctx context.Context, cfg *Config, r *http.Request, connectionID string, provider string, state string, durationSeconds float64) {
	if cfg == nil || !cfg.EventEnabled("websocket.connection."+state) {
		return
	}

	event := &events.WebSocketConnectionLifecycle{
		EventBase:       events.NewBase("websocket.connection."+state, events.SeverityInfo, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		ConnectionID:    connectionID,
		Path:            requestPath(r),
		Provider:        provider,
		State:           state,
		DurationSeconds: durationSeconds,
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func emitWebSocketToolCall(ctx context.Context, cfg *Config, r *http.Request, connectionID string, provider string, direction string, eventType string) {
	if cfg == nil || !cfg.EventEnabled("websocket.tool_call") {
		return
	}

	event := &events.WebSocketToolCall{
		EventBase:        events.NewBase("websocket.tool_call", events.SeverityInfo, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		ConnectionID:     connectionID,
		Path:             requestPath(r),
		Provider:         provider,
		Direction:        direction,
		MessageEventType: eventType,
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func emitUpstreamTimeout(ctx context.Context, cfg *Config, r *http.Request, upstreamURL string, timeoutSeconds int) {
	if cfg == nil || !cfg.EventEnabled("upstream.timeout") {
		return
	}
	event := &events.UpstreamTimeout{
		EventBase:      events.NewBase("upstream.timeout", events.SeverityError, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		UpstreamURL:    upstreamURL,
		TimeoutSeconds: timeoutSeconds,
		Path:           requestPath(r),
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func emitUpstream5xx(ctx context.Context, cfg *Config, r *http.Request, upstreamURL string, statusCode int, responseTimeMS int64) {
	if cfg == nil || !cfg.EventEnabled("upstream.5xx") {
		return
	}
	event := &events.Upstream5xx{
		EventBase:      events.NewBase("upstream.5xx", events.SeverityError, cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		UpstreamURL:    upstreamURL,
		StatusCode:     statusCode,
		Path:           requestPath(r),
		ResponseTimeMS: responseTimeMS,
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(ctx, cfg.WorkspaceID, event)
}

func ConfigOriginContext(cfg *Config) events.OriginContext {
	if cfg == nil {
		return events.OriginContext{}
	}
	actionType := ""
	if cfg.action != nil {
		actionType = cfg.action.GetType()
	}
	return events.OriginContext{
		OriginID:    cfg.ID,
		OriginName:  cfg.OriginName,
		Hostname:    cfg.Hostname,
		VersionID:   cfg.Version,
		WorkspaceID: cfg.WorkspaceID,
		ActionType:  actionType,
		Environment: cfg.Environment,
		Tags:        cfg.Tags,
	}
}

func requestPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.Path
}

func requestURLString(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.String()
}

func emitTypedCircuitEvent(cfg *Config, eventType string, severity string, targetURL string, failureCount int, cooldownSeconds int, recoverySeconds int) {
	if cfg == nil || !cfg.EventEnabled(eventType) {
		return
	}
	base := events.NewBase(eventType, severity, cfg.WorkspaceID, "")
	base.Origin = ConfigOriginContext(cfg)
	switch eventType {
	case "upstream.circuit_opened":
		events.Emit(context.Background(), cfg.WorkspaceID, &events.CircuitOpened{
			EventBase:       base,
			UpstreamURL:     targetURL,
			FailureCount:    failureCount,
			CooldownSeconds: cooldownSeconds,
		})
	case "upstream.circuit_closed":
		events.Emit(context.Background(), cfg.WorkspaceID, &events.CircuitClosed{
			EventBase:           base,
			UpstreamURL:         targetURL,
			RecoveryTimeSeconds: recoverySeconds,
		})
	}
}

func durationSecondsString(v int) string {
	if v <= 0 {
		return "0"
	}
	return strconv.Itoa(v)
}

// emitHealthChange emits an event when a load balancer target changes health status.
func emitHealthChange(cfg *Config, targetURL string, status string) {
	if cfg == nil || !cfg.EventEnabled("upstream.health_change") {
		return
	}
	severity := events.SeverityInfo
	if status == "unhealthy" {
		severity = events.SeverityWarning
	}
	event := &events.HealthChange{
		EventBase: events.NewBase("upstream.health_change", severity, cfg.WorkspaceID, ""),
		Target:    targetURL,
		Status:    status,
	}
	event.Origin = ConfigOriginContext(cfg)
	events.Emit(context.Background(), cfg.WorkspaceID, event)
}
