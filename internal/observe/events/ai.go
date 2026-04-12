// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

// AIRequestCompleted fires when an AI request successfully finishes
type AIRequestCompleted struct {
	EventBase
	Provider     string  `json:"provider"`
	Model        string  `json:"model"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
	LatencyMS    int64   `json:"latency_ms"`
	TtftMS       int64   `json:"ttft_ms,omitempty"`
	Agent        string  `json:"agent,omitempty"`
	Session      string  `json:"session,omitempty"`
	CacheHit     bool    `json:"cache_hit"`

	// Extended spend tracking fields
	TokensCached      int               `json:"tokens_cached,omitempty"`
	TokensReasoning   int               `json:"tokens_reasoning,omitempty"`
	KeyID             string            `json:"key_id,omitempty"`
	UserID            string            `json:"user_id,omitempty"`
	OriginalModel     string            `json:"original_model,omitempty"`
	GuardrailsRun     bool              `json:"guardrails_run,omitempty"`
	GuardrailsBlocked bool              `json:"guardrails_blocked,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
}

// AIBudgetExceeded fires when an AI request is blocked due to budget limits
type AIBudgetExceeded struct {
	EventBase
	Scope       string  `json:"scope"`
	ScopeValue  string  `json:"scope_value"`
	Period      string  `json:"period"`
	CurrentUSD  float64 `json:"current_usd"`
	LimitUSD    float64 `json:"limit_usd"`
	ActionTaken string  `json:"action_taken"`
}

// AIModelDowngraded fires when a request is auto-switched to a cheaper model
type AIModelDowngraded struct {
	EventBase
	OriginalModel     string  `json:"original_model"`
	DowngradedTo      string  `json:"downgraded_to"`
	BudgetUtilization float64 `json:"budget_utilization_pct"`
}

// AIGuardrailTriggered fires when a safety guardrail blocks or flags content
type AIGuardrailTriggered struct {
	EventBase
	GuardrailType string `json:"guardrail_type"`
	Action        string `json:"action"`
	Phase         string `json:"phase"`
	Detail        string `json:"detail"`
	Model         string `json:"model"`
	Agent         string `json:"agent,omitempty"`
}

// AIRequestStarted fires when an AI request begins processing
type AIRequestStarted struct {
	EventBase
	Model        string `json:"model"`
	Streaming    bool   `json:"streaming"`
	KeyID        string `json:"key_id,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	MessageCount int    `json:"message_count"`
	HasTools     bool   `json:"has_tools"`
}

// NewAIRequestStarted creates a new AIRequestStarted event
func NewAIRequestStarted(workspaceID, requestID, model string, streaming bool, keyID, userID string, messageCount int, hasTools bool) AIRequestStarted {
	return AIRequestStarted{
		EventBase:    NewBase("ai.request.started", SeverityInfo, workspaceID, requestID),
		Model:        model,
		Streaming:    streaming,
		KeyID:        keyID,
		UserID:       userID,
		MessageCount: messageCount,
		HasTools:     hasTools,
	}
}

// AIRequestFailed fires when an AI request fails
type AIRequestFailed struct {
	EventBase
	Model        string `json:"model"`
	Provider     string `json:"provider,omitempty"`
	ErrorCode    string `json:"error_code"`
	ErrorType    string `json:"error_type"`
	ErrorMessage string `json:"error_message"`
	HTTPStatus   int    `json:"http_status"`
	LatencyMs    int64  `json:"latency_ms"`
	Retries      int    `json:"retries"`
}

// NewAIRequestFailed creates a new AIRequestFailed event
func NewAIRequestFailed(workspaceID, requestID, model, provider, errorCode, errorType, errorMessage string, httpStatus int, latencyMs int64, retries int) AIRequestFailed {
	return AIRequestFailed{
		EventBase:    NewBase("ai.request.failed", SeverityError, workspaceID, requestID),
		Model:        model,
		Provider:     provider,
		ErrorCode:    errorCode,
		ErrorType:    errorType,
		ErrorMessage: errorMessage,
		HTTPStatus:   httpStatus,
		LatencyMs:    latencyMs,
		Retries:      retries,
	}
}

// AIProviderSelected fires when an AI provider is chosen for a request
type AIProviderSelected struct {
	EventBase
	Model    string `json:"model"`
	Provider string `json:"provider"`
	Strategy string `json:"strategy"`
}

// NewAIProviderSelected creates a new AIProviderSelected event
func NewAIProviderSelected(workspaceID, requestID, model, provider, strategy string) AIProviderSelected {
	return AIProviderSelected{
		EventBase: NewBase("ai.provider.selected", SeverityInfo, workspaceID, requestID),
		Model:     model,
		Provider:  provider,
		Strategy:  strategy,
	}
}

// AIProviderFallback fires when a request falls back to a different provider
type AIProviderFallback struct {
	EventBase
	Model        string `json:"model"`
	FromProvider string `json:"from_provider"`
	ToProvider   string `json:"to_provider"`
	Reason       string `json:"reason"`
}

// NewAIProviderFallback creates a new AIProviderFallback event
func NewAIProviderFallback(workspaceID, requestID, model, fromProvider, toProvider, reason string) AIProviderFallback {
	return AIProviderFallback{
		EventBase:    NewBase("ai.provider.fallback", SeverityWarning, workspaceID, requestID),
		Model:        model,
		FromProvider: fromProvider,
		ToProvider:   toProvider,
		Reason:       reason,
	}
}

// AIFailureDegraded fires when a subsystem enters degraded mode
type AIFailureDegraded struct {
	EventBase
	Subsystem   string `json:"subsystem"`
	Error       string `json:"error"`
	FailureMode string `json:"failure_mode"`
	ActionTaken string `json:"action_taken"`
}

// NewAIFailureDegraded creates a new AIFailureDegraded event
func NewAIFailureDegraded(workspaceID, requestID, subsystem, errMsg, failureMode, actionTaken string) AIFailureDegraded {
	return AIFailureDegraded{
		EventBase:   NewBase("ai.failure.degraded", SeverityWarning, workspaceID, requestID),
		Subsystem:   subsystem,
		Error:       errMsg,
		FailureMode: failureMode,
		ActionTaken: actionTaken,
	}
}

// AIHealthCheckFailed fires when a provider health check fails
type AIHealthCheckFailed struct {
	EventBase
	Provider            string `json:"provider"`
	Error               string `json:"error"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	CircuitState        string `json:"circuit_state"`
}

// NewAIHealthCheckFailed creates a new AIHealthCheckFailed event
func NewAIHealthCheckFailed(workspaceID, requestID, provider, errMsg string, consecutiveFailures int, circuitState string) AIHealthCheckFailed {
	return AIHealthCheckFailed{
		EventBase:           NewBase("ai.health.check_failed", SeverityCritical, workspaceID, requestID),
		Provider:            provider,
		Error:               errMsg,
		ConsecutiveFailures: consecutiveFailures,
		CircuitState:        circuitState,
	}
}

// AIHealthCheckRecovered fires when a provider recovers from health check failures
type AIHealthCheckRecovered struct {
	EventBase
	Provider   string `json:"provider"`
	DowntimeMs int64  `json:"downtime_ms"`
}

// NewAIHealthCheckRecovered creates a new AIHealthCheckRecovered event
func NewAIHealthCheckRecovered(workspaceID, requestID, provider string, downtimeMs int64) AIHealthCheckRecovered {
	return AIHealthCheckRecovered{
		EventBase:  NewBase("ai.health.check_recovered", SeverityInfo, workspaceID, requestID),
		Provider:   provider,
		DowntimeMs: downtimeMs,
	}
}

// AICacheHit fires when an AI response is served from cache
type AICacheHit struct {
	EventBase
	Model     string `json:"model"`
	CacheType string `json:"cache_type"`
	KeyHash   string `json:"key_hash,omitempty"`
}

// NewAICacheHit creates a new AICacheHit event
func NewAICacheHit(workspaceID, requestID, model, cacheType, keyHash string) AICacheHit {
	return AICacheHit{
		EventBase: NewBase("ai.cache.hit", SeverityInfo, workspaceID, requestID),
		Model:     model,
		CacheType: cacheType,
		KeyHash:   keyHash,
	}
}

// AICacheMiss fires when an AI response is not found in cache
type AICacheMiss struct {
	EventBase
	Model string `json:"model"`
}

// NewAICacheMiss creates a new AICacheMiss event
func NewAICacheMiss(workspaceID, requestID, model string) AICacheMiss {
	return AICacheMiss{
		EventBase: NewBase("ai.cache.miss", SeverityInfo, workspaceID, requestID),
		Model:     model,
	}
}

// AIAlertFired fires when an AI monitoring alert triggers
type AIAlertFired struct {
	EventBase
	RuleName  string                 `json:"rule_name"`
	Message   string                 `json:"message"`
	Condition string                 `json:"condition"`
	Tags      map[string]string      `json:"tags"`
	Context   map[string]interface{} `json:"context"`
}

// NewAIAlertFired creates a new AIAlertFired event with the given severity
func NewAIAlertFired(workspaceID, requestID, severity, ruleName, message, condition string, tags map[string]string, context map[string]interface{}) AIAlertFired {
	return AIAlertFired{
		EventBase: NewBase("ai.alert.fired", severity, workspaceID, requestID),
		RuleName:  ruleName,
		Message:   message,
		Condition: condition,
		Tags:      tags,
		Context:   context,
	}
}

// AIKeyRotated fires when an AI API key is rotated
type AIKeyRotated struct {
	EventBase
	OldKeyID  string `json:"old_key_id"`
	NewKeyID  string `json:"new_key_id"`
	GraceEnds string `json:"grace_ends"`
}

// NewAIKeyRotated creates a new AIKeyRotated event
func NewAIKeyRotated(workspaceID, requestID, oldKeyID, newKeyID, graceEnds string) AIKeyRotated {
	return AIKeyRotated{
		EventBase: NewBase("ai.key.rotated", SeverityInfo, workspaceID, requestID),
		OldKeyID:  oldKeyID,
		NewKeyID:  newKeyID,
		GraceEnds: graceEnds,
	}
}

// AIKeyRevoked fires when an AI API key is revoked
type AIKeyRevoked struct {
	EventBase
	KeyID  string `json:"key_id"`
	Reason string `json:"reason"`
}

// NewAIKeyRevoked creates a new AIKeyRevoked event
func NewAIKeyRevoked(workspaceID, requestID, keyID, reason string) AIKeyRevoked {
	return AIKeyRevoked{
		EventBase: NewBase("ai.key.revoked", SeverityWarning, workspaceID, requestID),
		KeyID:     keyID,
		Reason:    reason,
	}
}
