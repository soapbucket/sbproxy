// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

// HTTPSProxyAuthFailure fires when proxy authentication fails.
type HTTPSProxyAuthFailure struct {
	EventBase
	Reason string `json:"reason,omitempty"`
	Target string `json:"target,omitempty"`
}

// HTTPSProxyTargetDecision fires when a CONNECT target is classified as managed or unmanaged.
type HTTPSProxyTargetDecision struct {
	EventBase
	Target   string `json:"target,omitempty"`
	Decision string `json:"decision,omitempty"`
}

// HTTPSProxyTunnelLifecycle fires when an intercept or passthrough tunnel starts.
type HTTPSProxyTunnelLifecycle struct {
	EventBase
	Target string `json:"target,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

// HTTPSProxyMITMFailure fires when MITM setup fails for a managed host.
type HTTPSProxyMITMFailure struct {
	EventBase
	Target string `json:"target,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// HTTPSProxyCertificateGenerated fires when a MITM certificate is generated or served from cache.
type HTTPSProxyCertificateGenerated struct {
	EventBase
	Target    string `json:"target,omitempty"`
	CacheHit  bool   `json:"cache_hit,omitempty"`
	Generated bool   `json:"generated,omitempty"`
}

// HTTPSProxyDestinationBlocked fires when a destination is denied by ACL or safety checks.
type HTTPSProxyDestinationBlocked struct {
	EventBase
	Target string `json:"target,omitempty"`
	Reason string `json:"reason,omitempty"`
}
