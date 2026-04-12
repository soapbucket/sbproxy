// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/proxyerr"
)

// Validation limits
const (
	// MaxTimeoutDuration is the maximum allowed value for timeout duration.
	MaxTimeoutDuration = 1 * time.Minute // Maximum timeout: 1 minute
	// MaxBufferSize is the maximum allowed value for buffer size.
	MaxBufferSize      = 10 * 1024 * 1024 // Maximum buffer size: 10MB (10 * 1024 * 1024 bytes)
	// MaxRequestSize is the maximum allowed value for request size.
	MaxRequestSize     = 100 * 1024 * 1024 // Maximum request size: 100MB
)

// ValidateConfig validates all configuration settings for reasonable values
func (c *Config) ValidateConfig() error {
	var validationErrors []string

	// First, apply tag-based validation (applies defaults and validates)
	tagErrors := validateStruct(c, "")
	if len(tagErrors) > 0 {
		validationErrors = append(validationErrors, tagErrors...)
	}

	// Validate action-specific settings
	if c.action != nil {
		// Apply tag-based validation to action (includes BaseConnection validation via tags)
		actionTagErrors := validateStruct(c.action, "action")
		if len(actionTagErrors) > 0 {
			validationErrors = append(validationErrors, actionTagErrors...)
		}

		// Keep existing action-specific validation (non-tag-based checks)
		if err := c.validateAction(c.action); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("action validation: %v", err))
		}
	}

	// Validate policies
	for i, policy := range c.policies {
		// Apply tag-based validation to policy
		policyTagErrors := validateStruct(policy, fmt.Sprintf("policies[%d]", i))
		if len(policyTagErrors) > 0 {
			validationErrors = append(validationErrors, policyTagErrors...)
		}

		// Keep existing validation as additional checks
		if err := c.validatePolicy(policy); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("policies[%d]: %v", i, err))
		}
	}

	if len(validationErrors) > 0 {
		return proxyerr.ConfigValidationError(strings.Join(validationErrors, "; "))
	}

	return nil
}

// validateAction validates action-specific configuration
// Note: BaseConnection validation is now handled by tag-based validation in ValidateConfig()
func (c *Config) validateAction(action ActionConfig) error {
	var validationErrors []string

	// Action-specific validation is now handled by the plugin modules themselves
	// during Provision/Validate. The types below are from types.go and only matched
	// when the legacy config-local constructors were used. With the plugin registry,
	// actions are opaque plugin.ActionHandler instances wrapped in PluginActionAdapter,
	// so these type assertions no longer match. Keeping the config-type checks as a
	// safety net for any remaining direct construction paths.
	if wsConfig, ok := action.(*WebSocketConfig); ok {
		if err := c.validateWebSocketConfig(wsConfig); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("websocket: %v", err))
		}
	}

	if lbConfig, ok := action.(*LoadBalancerConfig); ok {
		if err := c.validateLoadBalancerConfig(lbConfig); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("loadbalancer: %v", err))
		}
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("%s", strings.Join(validationErrors, "; "))
	}

	return nil
}

// validateBaseConnection is no longer needed - BaseConnection validation
// is now handled automatically by tag-based validation in ValidateConfig()

// validateWebSocketConfig validates WebSocket-specific settings.
// Called when the action is a *WebSocketConfig from types.go (legacy path).
func (c *Config) validateWebSocketConfig(ws *WebSocketConfig) error {
	var validationErrors []string

	// Validate timeouts
	if ws.PongTimeout.Duration > 0 && ws.PongTimeout.Duration > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("pong_timeout: %v exceeds maximum of %v", ws.PongTimeout.Duration, MaxTimeoutDuration))
	}
	if ws.HandshakeTimeout.Duration > 0 && ws.HandshakeTimeout.Duration > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("handshake_timeout: %v exceeds maximum of %v", ws.HandshakeTimeout.Duration, MaxTimeoutDuration))
	}
	if ws.PingInterval.Duration > 0 && ws.PingInterval.Duration > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("ping_interval: %v exceeds maximum of %v", ws.PingInterval.Duration, MaxTimeoutDuration))
	}
	if ws.PoolMaxLifetime.Duration > 0 && ws.PoolMaxLifetime.Duration > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("pool_max_lifetime: %v exceeds maximum of %v", ws.PoolMaxLifetime.Duration, MaxTimeoutDuration))
	}
	if ws.PoolMaxIdleTime.Duration > 0 && ws.PoolMaxIdleTime.Duration > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("pool_max_idle_time: %v exceeds maximum of %v", ws.PoolMaxIdleTime.Duration, MaxTimeoutDuration))
	}
	if ws.PoolReconnectDelay.Duration > 0 && ws.PoolReconnectDelay.Duration > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("pool_reconnect_delay: %v exceeds maximum of %v", ws.PoolReconnectDelay.Duration, MaxTimeoutDuration))
	}

	// Validate buffer sizes
	if ws.ReadBufferSize > 0 && ws.ReadBufferSize > MaxBufferSize {
		validationErrors = append(validationErrors, fmt.Sprintf("read_buffer_size: %d bytes exceeds maximum of %d bytes (%dMB)", ws.ReadBufferSize, MaxBufferSize, MaxBufferSize/(1024*1024)))
	}
	if ws.WriteBufferSize > 0 && ws.WriteBufferSize > MaxBufferSize {
		validationErrors = append(validationErrors, fmt.Sprintf("write_buffer_size: %d bytes exceeds maximum of %d bytes (%dMB)", ws.WriteBufferSize, MaxBufferSize, MaxBufferSize/(1024*1024)))
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("%s", strings.Join(validationErrors, "; "))
	}

	return nil
}

// validateLoadBalancerConfig validates LoadBalancer-specific settings
// Note: BaseConnection, HealthCheck, and CircuitBreaker validation for targets
// is now handled by tag-based validation in ValidateConfig()
func (c *Config) validateLoadBalancerConfig(lb *LoadBalancerConfig) error {
	// All validation is now handled by tag-based validation
	// This function is kept for potential future non-tag validations
	return nil
}

// validatePolicy validates policy-specific settings
func (c *Config) validatePolicy(policy PolicyConfig) error {
	var validationErrors []string

	if accessor, ok := policy.(basePolicyAccessor); ok {
		if err := c.validatePolicyMatch(policy, accessor.BasePolicyPtr()); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
	}

	// Validate RequestLimitingPolicy
	if rlPolicy, ok := policy.(*RequestLimitingPolicy); ok {
		if rlPolicy.SizeLimits != nil {
			if rlPolicy.SizeLimits.MaxHeaderSize != "" {
				size, err := parseSizeToInt64WithError(rlPolicy.SizeLimits.MaxHeaderSize)
				if err != nil {
					validationErrors = append(validationErrors, fmt.Sprintf("size_limits.max_header_size: invalid format %q (must be human-readable like '10KB', '1MB'): %v", rlPolicy.SizeLimits.MaxHeaderSize, err))
				} else if size > MaxBufferSize {
					validationErrors = append(validationErrors, fmt.Sprintf("size_limits.max_header_size: %q (%d bytes) exceeds maximum of %d bytes (%dMB)", rlPolicy.SizeLimits.MaxHeaderSize, size, MaxBufferSize, MaxBufferSize/(1024*1024)))
				}
			}
			if rlPolicy.SizeLimits.MaxRequestSize != "" {
				size, err := parseSizeToInt64WithError(rlPolicy.SizeLimits.MaxRequestSize)
				if err != nil {
					validationErrors = append(validationErrors, fmt.Sprintf("size_limits.max_request_size: invalid format %q (must be human-readable like '10MB', '100MB'): %v", rlPolicy.SizeLimits.MaxRequestSize, err))
				} else if size > MaxRequestSize {
					validationErrors = append(validationErrors, fmt.Sprintf("size_limits.max_request_size: %q (%d bytes) exceeds maximum of %d bytes (%dMB)", rlPolicy.SizeLimits.MaxRequestSize, size, MaxRequestSize, MaxRequestSize/(1024*1024)))
				}
			}
		}
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("%s", strings.Join(validationErrors, "; "))
	}

	return nil
}

func (c *Config) validatePolicyMatch(policy PolicyConfig, base *BasePolicy) error {
	if base == nil || base.Match == nil {
		return nil
	}

	match := base.Match
	var validationErrors []string
	isWebSocketAction := false
	if c.action != nil {
		isWebSocketAction = c.action.GetType() == TypeWebSocket
	}

	if len(match.Phases) > 0 {
		for _, phase := range match.Phases {
			if phase != MessagePhaseUpgrade && phase != MessagePhaseMessage {
				validationErrors = append(validationErrors, fmt.Sprintf("match.phases contains unsupported value %q", phase))
			}
		}
	}

	if len(match.Protocols) > 0 {
		for _, protocol := range match.Protocols {
			if protocol != "http" && protocol != MessageProtocolWebSocket {
				validationErrors = append(validationErrors, fmt.Sprintf("match.protocols contains unsupported value %q", protocol))
			}
		}
	}

	if len(match.Directions) > 0 {
		for _, direction := range match.Directions {
			if direction != MessageDirectionClientToBackend && direction != MessageDirectionBackendToClient {
				validationErrors = append(validationErrors, fmt.Sprintf("match.directions contains unsupported value %q", direction))
			}
		}
		if !containsFold(match.Phases, MessagePhaseMessage) {
			validationErrors = append(validationErrors, "match.directions requires match.phases to include \"message\"")
		}
	}

	if len(match.EventTypes) > 0 && !containsFold(match.Protocols, MessageProtocolWebSocket) {
		validationErrors = append(validationErrors, "match.event_types requires match.protocols to include \"websocket\"")
	}

	if len(match.Providers) > 0 && !containsFold(match.Protocols, MessageProtocolWebSocket) {
		validationErrors = append(validationErrors, "match.providers requires match.protocols to include \"websocket\"")
	}

	if containsFold(match.Phases, MessagePhaseMessage) {
		if !policySupportsMessagePhase(policy) {
			validationErrors = append(validationErrors, fmt.Sprintf("policy type %q does not support websocket message phase", policy.GetType()))
		}
		if !isWebSocketAction {
			validationErrors = append(validationErrors, "message-phase policy matching requires a websocket action")
		}
	}

	if len(validationErrors) > 0 {
		return proxyerr.ConfigValidationError(strings.Join(validationErrors, "; "))
	}

	return nil
}

// parseSizeToInt64WithError parses a human-readable size string (e.g., "10MB", "100KB") to bytes.
func parseSizeToInt64WithError(sizeStr string) (int64, error) {
	if sizeStr == "" {
		return 0, fmt.Errorf("empty size string")
	}

	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	var numStr string
	var unit string
	for i, r := range sizeStr {
		if r >= '0' && r <= '9' {
			numStr += string(r)
		} else {
			unit = sizeStr[i:]
			break
		}
	}

	if numStr == "" {
		return 0, fmt.Errorf("no number found in size string: %q", sizeStr)
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in size string %q: %w", sizeStr, err)
	}

	var multiplier int64
	switch unit {
	case "KB", "K":
		multiplier = 1024
	case "MB", "M":
		multiplier = 1024 * 1024
	case "GB", "G":
		multiplier = 1024 * 1024 * 1024
	case "TB", "T":
		multiplier = 1024 * 1024 * 1024 * 1024
	case "B", "":
		multiplier = 1
	default:
		return 0, fmt.Errorf("invalid unit %q in size string %q (valid units: B, KB/K, MB/M, GB/G, TB/T)", unit, sizeStr)
	}

	return num * multiplier, nil
}

// ValidateHTTPClientConfig validates HTTPClientConfig settings

