// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"fmt"
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
	// MaxProcessableSize is the maximum allowed value for processable size.
	MaxProcessableSize = 100 * 1024 * 1024 // Maximum processable body size: 100MB
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

	// Validate WebSocket-specific settings
	if wsAction, ok := action.(*WebSocketAction); ok {
		if err := c.validateWebSocketConfig(&wsAction.WebSocketConfig); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("websocket: %v", err))
		}
	} else if wsConfig, ok := action.(*WebSocketConfig); ok {
		if err := c.validateWebSocketConfig(wsConfig); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("websocket: %v", err))
		}
	}

	// Validate GraphQL-specific settings
	if gqlConfig, ok := action.(*GraphQLConfig); ok {
		if err := c.validateGraphQLConfig(gqlConfig); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("graphql: %v", err))
		}
	}

	// Validate gRPC-specific settings
	if grpcConfig, ok := action.(*GRPCConfig); ok {
		if err := c.validateGRPCConfig(grpcConfig); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("grpc: %v", err))
		}
	}

	// Validate LoadBalancer-specific settings
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

// validateWebSocketConfig validates WebSocket-specific settings
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

// validateGraphQLConfig validates GraphQL-specific settings
func (c *Config) validateGraphQLConfig(gql *GraphQLConfig) error {
	// GraphQL config doesn't have timeout/buffer settings that need validation
	// Cache sizes are reasonable (defaults are 1000-10000)
	return nil
}

// validateGRPCConfig validates gRPC-specific settings
func (c *Config) validateGRPCConfig(grpc *GRPCConfig) error {
	var validationErrors []string

	// Validate message sizes (gRPC message sizes can be larger than buffers)
	// But we still want reasonable limits
	maxGRPCMessageSize := 50 * 1024 * 1024 // 50MB for gRPC messages
	if grpc.MaxCallRecvMsgSize > 0 && grpc.MaxCallRecvMsgSize > maxGRPCMessageSize {
		validationErrors = append(validationErrors, fmt.Sprintf("max_call_recv_msg_size: %d bytes exceeds maximum of %d bytes (%dMB)", grpc.MaxCallRecvMsgSize, maxGRPCMessageSize, maxGRPCMessageSize/(1024*1024)))
	}
	if grpc.MaxCallSendMsgSize > 0 && grpc.MaxCallSendMsgSize > maxGRPCMessageSize {
		validationErrors = append(validationErrors, fmt.Sprintf("max_call_send_msg_size: %d bytes exceeds maximum of %d bytes (%dMB)", grpc.MaxCallSendMsgSize, maxGRPCMessageSize, maxGRPCMessageSize/(1024*1024)))
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
		if rlPolicy.Protection != nil {
			if rlPolicy.Protection.Timeout.Duration > 0 && rlPolicy.Protection.Timeout.Duration > MaxTimeoutDuration {
				validationErrors = append(validationErrors, fmt.Sprintf("protection.timeout: %v exceeds maximum of %v", rlPolicy.Protection.Timeout.Duration, MaxTimeoutDuration))
			}
		}
	}

	// Validate DDoSProtectionPolicy
	if ddosPolicy, ok := policy.(*DDoSProtectionPolicy); ok {
		if ddosPolicy.Mitigation != nil {
			if ddosPolicy.Mitigation.ProofOfWork != nil {
				if ddosPolicy.Mitigation.ProofOfWork.Timeout != "" {
					duration, err := time.ParseDuration(ddosPolicy.Mitigation.ProofOfWork.Timeout)
					if err != nil {
						validationErrors = append(validationErrors, fmt.Sprintf("mitigation.proof_of_work.timeout: invalid format %q (must be human-readable like '30s', '1m')", ddosPolicy.Mitigation.ProofOfWork.Timeout))
					} else if duration > MaxTimeoutDuration {
						validationErrors = append(validationErrors, fmt.Sprintf("mitigation.proof_of_work.timeout: %v exceeds maximum of %v", duration, MaxTimeoutDuration))
					}
				}
			}
			if ddosPolicy.Mitigation.JavaScriptChallenge != nil {
				if ddosPolicy.Mitigation.JavaScriptChallenge.Timeout != "" {
					duration, err := time.ParseDuration(ddosPolicy.Mitigation.JavaScriptChallenge.Timeout)
					if err != nil {
						validationErrors = append(validationErrors, fmt.Sprintf("mitigation.javascript_challenge.timeout: invalid format %q (must be human-readable like '60s', '1m')", ddosPolicy.Mitigation.JavaScriptChallenge.Timeout))
					} else if duration > MaxTimeoutDuration {
						validationErrors = append(validationErrors, fmt.Sprintf("mitigation.javascript_challenge.timeout: %v exceeds maximum of %v", duration, MaxTimeoutDuration))
					}
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
		_, isWebSocketAction = c.action.(*WebSocketAction)
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

// ValidateHTTPClientConfig validates HTTPClientConfig settings
func ValidateHTTPClientConfig(config *httputil.HTTPClientConfig) error {
	var validationErrors []string

	// Validate timeouts
	if config.Timeout > 0 && config.Timeout > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("timeout: %v exceeds maximum of %v", config.Timeout, MaxTimeoutDuration))
	}
	if config.IdleConnTimeout > 0 && config.IdleConnTimeout > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("idle_conn_timeout: %v exceeds maximum of %v", config.IdleConnTimeout, MaxTimeoutDuration))
	}
	if config.ResponseHeaderTimeout > 0 && config.ResponseHeaderTimeout > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("response_header_timeout: %v exceeds maximum of %v", config.ResponseHeaderTimeout, MaxTimeoutDuration))
	}
	if config.ExpectContinueTimeout > 0 && config.ExpectContinueTimeout > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("expect_continue_timeout: %v exceeds maximum of %v", config.ExpectContinueTimeout, MaxTimeoutDuration))
	}
	if config.TLSHandshakeTimeout > 0 && config.TLSHandshakeTimeout > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("tls_handshake_timeout: %v exceeds maximum of %v", config.TLSHandshakeTimeout, MaxTimeoutDuration))
	}
	if config.DialTimeout > 0 && config.DialTimeout > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("dial_timeout: %v exceeds maximum of %v", config.DialTimeout, MaxTimeoutDuration))
	}
	if config.KeepAlive > 0 && config.KeepAlive > MaxTimeoutDuration {
		validationErrors = append(validationErrors, fmt.Sprintf("keep_alive: %v exceeds maximum of %v", config.KeepAlive, MaxTimeoutDuration))
	}

	// Validate buffer sizes
	if config.WriteBufferSize > 0 && config.WriteBufferSize > MaxBufferSize {
		validationErrors = append(validationErrors, fmt.Sprintf("write_buffer_size: %d bytes exceeds maximum of %d bytes (%dMB)", config.WriteBufferSize, MaxBufferSize, MaxBufferSize/(1024*1024)))
	}
	if config.ReadBufferSize > 0 && config.ReadBufferSize > MaxBufferSize {
		validationErrors = append(validationErrors, fmt.Sprintf("read_buffer_size: %d bytes exceeds maximum of %d bytes (%dMB)", config.ReadBufferSize, MaxBufferSize, MaxBufferSize/(1024*1024)))
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("%s", strings.Join(validationErrors, "; "))
	}

	return nil
}

