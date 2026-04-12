// types.go defines Kubernetes Gateway API resource types used by the reconciler.
package k8s

import "time"

// GatewayClass represents a class of Gateways (maps to gateway.networking.k8s.io/GatewayClass).
type GatewayClass struct {
	Name           string             `json:"name"`
	ControllerName string             `json:"controller_name"` // e.g., "soapbucket.io/proxy"
	Description    string             `json:"description,omitempty"`
	Parameters     map[string]any     `json:"parameters,omitempty"`
	Status         GatewayClassStatus `json:"status,omitempty"`
}

// GatewayClassStatus tracks the acceptance and programming state of a GatewayClass.
type GatewayClassStatus struct {
	Accepted    bool      `json:"accepted"`
	Programmed  bool      `json:"programmed"`
	Message     string    `json:"message,omitempty"`
	LastUpdated time.Time `json:"last_updated,omitempty"`
}

// Gateway represents a gateway instance.
type Gateway struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Class     string            `json:"class"` // Reference to GatewayClass
	Listeners []GatewayListener `json:"listeners"`
	Status    GatewayStatus     `json:"status,omitempty"`
}

// GatewayListener defines a single listener on a Gateway.
type GatewayListener struct {
	Name     string            `json:"name"`
	Port     int               `json:"port"`
	Protocol string            `json:"protocol"` // HTTP, HTTPS, TLS, TCP
	Hostname string            `json:"hostname,omitempty"`
	TLS      *GatewayTLSConfig `json:"tls,omitempty"`
}

// GatewayTLSConfig holds TLS configuration for a listener.
type GatewayTLSConfig struct {
	Mode           string `json:"mode,omitempty"` // Terminate, Passthrough
	CertificateRef string `json:"certificate_ref,omitempty"`
}

// GatewayStatus holds runtime status of a Gateway.
type GatewayStatus struct {
	Addresses  []GatewayAddress `json:"addresses,omitempty"`
	Conditions []Condition      `json:"conditions,omitempty"`
}

// GatewayAddress is a network address assigned to a Gateway.
type GatewayAddress struct {
	Type  string `json:"type"` // IPAddress, Hostname
	Value string `json:"value"`
}

// Condition describes the state of a resource at a point in time.
type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"` // True, False, Unknown
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
	LastTransitionTime time.Time `json:"last_transition_time,omitempty"`
}

// HTTPRoute represents an HTTP routing rule.
type HTTPRoute struct {
	Name      string          `json:"name"`
	Namespace string          `json:"namespace,omitempty"`
	Hostnames []string        `json:"hostnames,omitempty"`
	ParentRef string          `json:"parent_ref"` // Reference to Gateway
	Rules     []HTTPRouteRule `json:"rules"`
}

// HTTPRouteRule defines a single routing rule within an HTTPRoute.
type HTTPRouteRule struct {
	Matches     []HTTPRouteMatch  `json:"matches,omitempty"`
	Filters     []HTTPRouteFilter `json:"filters,omitempty"`
	BackendRefs []BackendRef      `json:"backend_refs,omitempty"`
	Timeouts    *RouteTimeouts    `json:"timeouts,omitempty"`
}

// HTTPRouteMatch specifies conditions under which a rule applies.
type HTTPRouteMatch struct {
	Path    *PathMatch    `json:"path,omitempty"`
	Headers []HeaderMatch `json:"headers,omitempty"`
	Query   []QueryMatch  `json:"query,omitempty"`
	Method  string        `json:"method,omitempty"`
}

// PathMatch describes how to match an HTTP request path.
type PathMatch struct {
	Type  string `json:"type"` // Exact, PathPrefix, RegularExpression
	Value string `json:"value"`
}

// HeaderMatch describes how to match an HTTP header.
type HeaderMatch struct {
	Type  string `json:"type"` // Exact, RegularExpression
	Name  string `json:"name"`
	Value string `json:"value"`
}

// QueryMatch describes how to match a query parameter.
type QueryMatch struct {
	Type  string `json:"type"` // Exact, RegularExpression
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HTTPRouteFilter defines processing steps applied to a request or response.
type HTTPRouteFilter struct {
	Type                   string                 `json:"type"` // RequestHeaderModifier, ResponseHeaderModifier, URLRewrite, RequestRedirect
	RequestHeaderModifier  *HeaderModifier        `json:"request_header_modifier,omitempty"`
	ResponseHeaderModifier *HeaderModifier        `json:"response_header_modifier,omitempty"`
	URLRewrite             *URLRewriteFilter      `json:"url_rewrite,omitempty"`
	RequestRedirect        *RequestRedirectFilter `json:"request_redirect,omitempty"`
}

// HeaderModifier describes modifications to HTTP headers.
type HeaderModifier struct {
	Set    map[string]string `json:"set,omitempty"`
	Add    map[string]string `json:"add,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

// URLRewriteFilter defines URL rewrite behavior.
type URLRewriteFilter struct {
	Hostname string     `json:"hostname,omitempty"`
	Path     *PathMatch `json:"path,omitempty"`
}

// RequestRedirectFilter defines redirect behavior.
type RequestRedirectFilter struct {
	Scheme     string     `json:"scheme,omitempty"`
	Hostname   string     `json:"hostname,omitempty"`
	Port       int        `json:"port,omitempty"`
	Path       *PathMatch `json:"path,omitempty"`
	StatusCode int        `json:"status_code,omitempty"` // 301 or 302
}

// BackendRef references a backend service.
type BackendRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Port      int    `json:"port"`
	Weight    int    `json:"weight,omitempty"` // Default: 1
}

// RouteTimeouts configures timeout behavior for a route.
type RouteTimeouts struct {
	Request        string `json:"request,omitempty"`         // e.g., "30s"
	BackendRequest string `json:"backend_request,omitempty"` // e.g., "10s"
}

// GRPCRoute represents a gRPC routing rule.
type GRPCRoute struct {
	Name      string          `json:"name"`
	Namespace string          `json:"namespace,omitempty"`
	Hostnames []string        `json:"hostnames,omitempty"`
	ParentRef string          `json:"parent_ref"`
	Rules     []GRPCRouteRule `json:"rules"`
}

// GRPCRouteRule defines a single routing rule within a GRPCRoute.
type GRPCRouteRule struct {
	Matches     []GRPCRouteMatch `json:"matches,omitempty"`
	BackendRefs []BackendRef     `json:"backend_refs,omitempty"`
}

// GRPCRouteMatch specifies conditions for matching a gRPC request.
type GRPCRouteMatch struct {
	Method  *GRPCMethodMatch `json:"method,omitempty"`
	Headers []HeaderMatch    `json:"headers,omitempty"`
}

// GRPCMethodMatch matches gRPC requests by service and method name.
type GRPCMethodMatch struct {
	Type    string `json:"type"` // Exact, RegularExpression
	Service string `json:"service"`
	Method  string `json:"method,omitempty"`
}

// AIRoute extends HTTPRoute with AI-specific configuration (SoapBucket custom CRD).
type AIRoute struct {
	HTTPRoute
	Provider   string        `json:"provider"`
	Model      string        `json:"model,omitempty"`
	Guardrails []string      `json:"guardrails,omitempty"`
	Budget     *BudgetConfig `json:"budget,omitempty"`
}

// BudgetConfig defines spending limits for AI routes.
type BudgetConfig struct {
	MaxDailyUSD         float64 `json:"max_daily_usd,omitempty"`
	MaxMonthlyUSD       float64 `json:"max_monthly_usd,omitempty"`
	MaxTokensPerRequest int     `json:"max_tokens_per_request,omitempty"`
}
