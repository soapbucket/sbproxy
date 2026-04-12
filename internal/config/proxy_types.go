// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"github.com/soapbucket/sbproxy/internal/middleware/compression"
	"github.com/soapbucket/sbproxy/internal/middleware/cors"
)

// ProxyHeaderConfig controls proxy header behavior
type ProxyHeaderConfig struct {
	// ===== Trust Model (Envoy-inspired) =====

	// Trust mode for proxy headers (inspired by Envoy's use_remote_address)
	// Default: "trust_all"
	TrustMode TrustMode `json:"trust_mode,omitempty" yaml:"trust_mode,omitempty"`

	// Trusted proxy CIDRs (when trust_mode = trust_trusted_proxies)
	// Default: nil (no restrictions)
	TrustedProxies []string `json:"trusted_proxies,omitempty" yaml:"trusted_proxies,omitempty"`

	// Number of trusted proxy hops to preserve in X-Forwarded-For
	// Default: 0 (don't trim chain)
	TrustedHops int `json:"trusted_hops,omitempty" yaml:"trusted_hops,omitempty"`

	// ===== Standard Forwarding Headers =====

	// X-Forwarded-For configuration (nil = default "append" mode)
	XForwardedFor *XForwardedForConfig `json:"x_forwarded_for,omitempty" yaml:"x_forwarded_for,omitempty"`

	// X-Forwarded-Proto configuration (nil = default "set" mode)
	XForwardedProto *XForwardedProtoConfig `json:"x_forwarded_proto,omitempty" yaml:"x_forwarded_proto,omitempty"`

	// X-Forwarded-Host configuration (nil = default "set" mode)
	XForwardedHost *XForwardedHostConfig `json:"x_forwarded_host,omitempty" yaml:"x_forwarded_host,omitempty"`

	// X-Forwarded-Port configuration (nil = default "set" mode)
	XForwardedPort *XForwardedPortConfig `json:"x_forwarded_port,omitempty" yaml:"x_forwarded_port,omitempty"`

	// Disable X-Real-IP header (omit or false to enable)
	// Default: false (X-Real-IP is sent)
	DisableXRealIP bool `json:"disable_x_real_ip,omitempty" yaml:"disable_x_real_ip,omitempty"`

	// ===== RFC 7239 Forwarded Header =====

	// RFC 7239 Forwarded header configuration (nil = not enabled)
	Forwarded *ForwardedHeaderConfig `json:"forwarded,omitempty" yaml:"forwarded,omitempty"`

	// ===== Via Header =====

	// Via header configuration (nil = enabled with "soapbucket" identifier)
	Via *ViaHeaderConfig `json:"via,omitempty" yaml:"via,omitempty"`

	// ===== Enrichment Headers (disabled by default, opt-in per origin) =====

	// UserAgent adds X-SB-UA header with parsed user-agent details (semicolon-separated key=value)
	// Example: family=Chrome;major=120;os_family=macOS;device_family=Desktop
	UserAgent *EnrichmentHeaderConfig `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`

	// Location adds X-SB-Location header with GeoIP location data (semicolon-separated key=value)
	// Example: country=United States;country_code=US;continent=North America;asn=15169
	Location *EnrichmentHeaderConfig `json:"location,omitempty" yaml:"location,omitempty"`

	// Signature adds X-SB-Signature header with the request fingerprint hash
	Signature *EnrichmentHeaderConfig `json:"signature,omitempty" yaml:"signature,omitempty"`

	// DisableForwarded disables all forwarding headers (X-Forwarded-*, X-Real-IP, Forwarded)
	DisableForwarded bool `json:"disable_forwarded,omitempty" yaml:"disable_forwarded,omitempty"`

	// ===== Header Security =====

	// Disable automatic removal of server identification headers
	// Default: false (Server, X-Powered-By headers ARE removed for security)
	DisableServerHeaderRemoval bool `json:"disable_server_header_removal,omitempty" yaml:"disable_server_header_removal,omitempty"`

	// Strip headers matching patterns before sending to client
	// Supports wildcards: "X-Internal-*", "X-Debug-*"
	// Default: nil (no additional stripping)
	StripInternalHeaders []string `json:"strip_internal_headers,omitempty" yaml:"strip_internal_headers,omitempty"`

	// Strip headers matching patterns before sending to upstream
	// Supports wildcards: "X-Client-Internal-*"
	// Default: nil (no additional stripping)
	StripClientHeaders []string `json:"strip_client_headers,omitempty" yaml:"strip_client_headers,omitempty"`

	// ===== Hop-by-Hop Headers =====

	// Additional hop-by-hop headers to remove (beyond standard list)
	// Standard list always removed: Connection, Keep-Alive, Proxy-Authenticate,
	// Proxy-Authorization, TE, Trailers, Transfer-Encoding, Upgrade
	// Default: nil (only standard list removed)
	AdditionalHopByHopHeaders []string `json:"additional_hop_by_hop_headers,omitempty" yaml:"additional_hop_by_hop_headers,omitempty"`

	// ===== Header Limits =====

	// Maximum request header size (prevents attacks)
	// Default: 1MB
	MaxRequestHeaderSize string `json:"max_request_header_size,omitempty" yaml:"max_request_header_size,omitempty"`

	// Maximum response header size
	// Default: 1MB
	MaxResponseHeaderSize string `json:"max_response_header_size,omitempty" yaml:"max_response_header_size,omitempty"`

	// Maximum number of headers (prevents attacks)
	// Default: 100
	MaxHeaderCount int `json:"max_header_count,omitempty" yaml:"max_header_count,omitempty"`

	// ===== Host Header Handling =====

	// Preserve original host header (don't override with upstream host)
	// Default: false (override with upstream host from URL)
	PreserveHostHeader bool `json:"preserve_host_header,omitempty" yaml:"preserve_host_header,omitempty"`

	// Custom host header to send to upstream (overrides target URL host)
	// Default: "" (use target URL host)
	OverrideHost string `json:"override_host,omitempty" yaml:"override_host,omitempty"`

	// ===== Case Handling =====

	// Disable automatic header name normalization to canonical form
	// Default: false (normalization enabled - recommended)
	DisableHeaderNormalization bool `json:"disable_header_normalization,omitempty" yaml:"disable_header_normalization,omitempty"`
}

// XForwardedForConfig controls X-Forwarded-For behavior
type XForwardedForConfig struct {
	// Mode for X-Forwarded-For header
	// Default: "append"
	Mode XFFMode `json:"mode,omitempty" yaml:"mode,omitempty"`
}

// XForwardedProtoConfig controls X-Forwarded-Proto behavior
type XForwardedProtoConfig struct {
	// Mode for X-Forwarded-Proto header
	// Default: "set"
	Mode XFPMode `json:"mode,omitempty" yaml:"mode,omitempty"`
}

// XForwardedHostConfig controls X-Forwarded-Host behavior
type XForwardedHostConfig struct {
	// Mode for X-Forwarded-Host header
	// Default: "set"
	Mode XFHMode `json:"mode,omitempty" yaml:"mode,omitempty"`
}

// XForwardedPortConfig controls X-Forwarded-Port behavior
type XForwardedPortConfig struct {
	// Mode for X-Forwarded-Port header
	// Default: "set"
	Mode XFPMode `json:"mode,omitempty" yaml:"mode,omitempty"`
}

// ForwardedHeaderConfig for RFC 7239
type ForwardedHeaderConfig struct {
	// Enable RFC 7239 Forwarded header
	// Default: false (not sent - uses X-Forwarded-* legacy headers only)
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`

	// Disable legacy X-Forwarded-* headers when Forwarded is enabled.
	// Default: false (send both for compatibility).
	DisableLegacy bool `json:"disable_legacy,omitempty" yaml:"disable_legacy,omitempty"`

	// Deprecated alias for backward compatibility.
	// When set, this overrides DisableLegacy.
	IncludeLegacy *bool `json:"include_legacy,omitempty" yaml:"include_legacy,omitempty"`

	// Obfuscate client IP (use random identifier instead of real IP)
	// Default: false (send real IP)
	ObfuscateIP bool `json:"obfuscate_ip,omitempty" yaml:"obfuscate_ip,omitempty"`

	// Optional by= node identifier to add to the Forwarded header.
	// Example: "soapbucket" or "proxy.internal"
	By string `json:"by,omitempty" yaml:"by,omitempty"`
}

// ViaHeaderConfig controls Via header behavior
type ViaHeaderConfig struct {
	// Disable Via header (omit or false to enable)
	// Default: false (Via header is sent with constant "soapbucket" identifier)
	// Format: "1.1 soapbucket" or "2 soapbucket" depending on protocol
	Disable bool `json:"disable,omitempty" yaml:"disable,omitempty"`
}

// EnrichmentHeaderConfig controls optional enrichment headers
type EnrichmentHeaderConfig struct {
	// Enable turns on this header (default: false)
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`
	// Header overrides the default header name
	Header string `json:"header,omitempty" yaml:"header,omitempty"`
}

// TrustMode defines how to trust incoming proxy headers
type TrustMode string

const (
	// TrustAll is a constant for trust all.
	TrustAll TrustMode = "trust_all"
	// TrustTrustedProxies is a constant for trust trusted proxies.
	TrustTrustedProxies TrustMode = "trust_trusted_proxies"
	// TrustNone is a constant for trust none.
	TrustNone TrustMode = "trust_none"
)

// XFFMode defines X-Forwarded-For behavior
type XFFMode string

const (
	// XFFAppend is a constant for xff append.
	XFFAppend XFFMode = "append" // Add to chain
	// XFFReplace is a constant for xff replace.
	XFFReplace XFFMode = "replace" // Overwrite with client IP
	// XFFOff is a constant for xff off.
	XFFOff XFFMode = "off" // Don't send
)

// XFPMode defines X-Forwarded-Proto behavior
type XFPMode string

const (
	// XFPSet is a constant for xfp set.
	XFPSet XFPMode = "set" // Always set
	// XFPPreserve is a constant for xfp preserve.
	XFPPreserve XFPMode = "preserve" // Keep if present
	// XFPOff is a constant for xfp off.
	XFPOff XFPMode = "off" // Don't send
)

// XFHMode defines X-Forwarded-Host behavior
type XFHMode string

const (
	// XFHSet is a constant for xfh set.
	XFHSet XFHMode = "set"
	// XFHPreserve is a constant for xfh preserve.
	XFHPreserve XFHMode = "preserve"
	// XFHOff is a constant for xfh off.
	XFHOff XFHMode = "off"
)

// ProxyProtocolConfig controls RFC-level proxy protocol behavior.
// These settings are separate from header behavior (ProxyHeaderConfig) and
// streaming behavior (StreamingProxyConfig).
type ProxyProtocolConfig struct {
	// ===== Method Controls =====

	// Allow TRACE method to be forwarded to upstream.
	// Default: false (TRACE is blocked with 405 to prevent credential leakage per RFC 9110 Section 9.3.8)
	AllowTrace bool `json:"allow_trace,omitempty" yaml:"allow_trace,omitempty"`

	// ===== Request Validation =====

	// Disable rejection of requests with both Content-Length and Transfer-Encoding headers.
	// Default: false (ambiguous requests are rejected with 400 to prevent request smuggling per RFC 9112 Section 6.3)
	// WARNING: disabling this weakens request smuggling protection.
	DisableRequestSmuggling bool `json:"disable_request_smuggling_protection,omitempty" yaml:"disable_request_smuggling_protection,omitempty"`

	// ===== Max-Forwards =====

	// Disable Max-Forwards header handling for OPTIONS requests.
	// Default: false (Max-Forwards is decremented per RFC 9110 Section 7.6.2)
	DisableMaxForwards bool `json:"disable_max_forwards,omitempty" yaml:"disable_max_forwards,omitempty"`

	// ===== Response Enrichment =====

	// Disable automatic Date header on responses when missing from upstream.
	// Default: false (Date is added per RFC 9110 Section 6.6.1)
	DisableAutoDate bool `json:"disable_auto_date,omitempty" yaml:"disable_auto_date,omitempty"`

	// Interim response forwarding controls (1xx responses such as 103 Early Hints).
	InterimResponses *InterimResponseConfig `json:"interim_responses,omitempty" yaml:"interim_responses,omitempty"`

	// RFC 8470: Early data handling for TLS 0-RTT requests.
	EarlyData *EarlyDataConfig `json:"early_data,omitempty" yaml:"early_data,omitempty"`

	// RFC 9110 Section 10.1.1: Expect: 100-continue handling.
	ExpectContinue *ExpectContinueConfig `json:"expect_continue,omitempty" yaml:"expect_continue,omitempty"`

	// RFC 7233: Range request handling.
	RangeRequests *RangeRequestConfig `json:"range_requests,omitempty" yaml:"range_requests,omitempty"`
}

// InterimResponseConfig controls proxy handling of upstream 1xx responses.
type InterimResponseConfig struct {
	// Forward 100 Continue responses to downstream clients.
	// Default: false.
	Forward100Continue bool `json:"forward_100_continue,omitempty" yaml:"forward_100_continue,omitempty"`

	// Forward 103 Early Hints responses to downstream clients.
	// Default: false.
	Forward103EarlyHints bool `json:"forward_103_early_hints,omitempty" yaml:"forward_103_early_hints,omitempty"`

	// Forward any other 1xx responses that are not otherwise matched.
	// Default: false.
	ForwardOther bool `json:"forward_other,omitempty" yaml:"forward_other,omitempty"`
}

// StreamingProxyConfig controls chunking and trailers
type StreamingProxyConfig struct {
	// ===== Chunked Transfer Encoding =====

	// Disable chunked transfer encoding for requests to upstream
	// Default: false (chunking enabled when Content-Length unknown)
	DisableRequestChunking bool `json:"disable_request_chunking,omitempty" yaml:"disable_request_chunking,omitempty"`

	// Disable chunked transfer encoding for responses to client
	// Default: false (chunking enabled for HTTP/1.1 responses)
	DisableResponseChunking bool `json:"disable_response_chunking,omitempty" yaml:"disable_response_chunking,omitempty"`

	// Minimum size for chunked response (smaller responses buffered)
	// Default: 8KB
	ChunkThreshold string `json:"chunk_threshold,omitempty" yaml:"chunk_threshold,omitempty"`

	// Chunk size for streaming (balance between efficiency and latency)
	// Default: 32KB
	ChunkSize string `json:"chunk_size,omitempty" yaml:"chunk_size,omitempty"`

	// ===== Trailer Headers =====

	// Disable trailer header support (breaks gRPC if disabled)
	// Default: false (trailers enabled - required for gRPC)
	DisableTrailers bool `json:"disable_trailers,omitempty" yaml:"disable_trailers,omitempty"`

	// Disable trailer announcement in response headers
	// Default: false (announce trailers via Trailer: header)
	DisableTrailerAnnouncement bool `json:"disable_trailer_announcement,omitempty" yaml:"disable_trailer_announcement,omitempty"`

	// Disable forwarding trailers from upstream to client
	// Default: false (forward trailers)
	DisableTrailerForwarding bool `json:"disable_trailer_forwarding,omitempty" yaml:"disable_trailer_forwarding,omitempty"`

	// Generate trailers (e.g., computed checksums, timing)
	// Default: nil (no generated trailers)
	GenerateTrailers []TrailerGenerator `json:"generate_trailers,omitempty" yaml:"generate_trailers,omitempty"`

	// ===== Buffering =====

	// Disable buffering of small responses
	// Default: false (small responses are buffered to reduce syscalls)
	DisableSmallResponseBuffering bool `json:"disable_small_response_buffering,omitempty" yaml:"disable_small_response_buffering,omitempty"`

	// Buffer size threshold - responses smaller than this are buffered entirely
	// Default: 64KB
	BufferSizeThreshold string `json:"buffer_size_threshold,omitempty" yaml:"buffer_size_threshold,omitempty"`

	// Buffer size for proxying (affects memory usage per request)
	// Default: 32KB
	ProxyBufferSize string `json:"proxy_buffer_size,omitempty" yaml:"proxy_buffer_size,omitempty"`

	// ===== Flushing =====

	// Flush interval override (omit for auto-detect, -1 for force immediate, >0 for periodic)
	// Default: omitted (auto-detect based on content-type and protocol)
	// Auto-detect handles: SSE, gRPC, HTTP/2 bidirectional, chunked encoding
	// RECOMMENDATION: Omit this field - auto-detection works for 99% of cases
	DefaultFlushInterval string `json:"default_flush_interval,omitempty" yaml:"default_flush_interval,omitempty"`

	// Force flush headers immediately (auto-detected for streaming protocols)
	// Default: omitted (headers flushed automatically when needed)
	// RECOMMENDATION: Omit this field - auto-detection works for 99% of cases
	ForceFlushHeaders bool `json:"force_flush_headers,omitempty" yaml:"force_flush_headers,omitempty"`
}

// TrailerGenerator defines a generated trailer header
type TrailerGenerator struct {
	// Trailer header name
	Name string `json:"name" yaml:"name"`

	// Type of trailer to generate
	Type TrailerType `json:"type" yaml:"type"`

	// For checksum: "md5", "sha256", etc.
	// For timing: duration calculation
	// For custom: CEL expression
	Value string `json:"value" yaml:"value"`
}

// CompressionConfig is an alias for the compression middleware config type.
type CompressionConfig = compression.Config

// CORSConfig is an alias for the cors middleware config type.
type CORSConfig = cors.Config

// ProxyStatusConfig controls RFC 9209 Proxy-Status header generation
type ProxyStatusConfig struct {
	// Enable Proxy-Status header on responses.
	// Default: false
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`

	// Proxy name used in the Proxy-Status header.
	// Default: "soapbucket"
	ProxyName string `json:"proxy_name,omitempty" yaml:"proxy_name,omitempty"`
}

// URINormalizationConfig controls request URI normalization (RFC 3986 Section 6)
type URINormalizationConfig struct {
	// Enable URI normalization on incoming requests.
	// Default: false (preserve original URI)
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`

	// Remove dot segments (. and ..) from paths.
	// Default: true when enabled
	DecodeDotSegments *bool `json:"decode_dot_segments,omitempty" yaml:"decode_dot_segments,omitempty"`

	// Decode unreserved percent-encoded characters (RFC 3986 Section 2.3).
	// Default: true when enabled
	DecodeUnreserved *bool `json:"decode_unreserved,omitempty" yaml:"decode_unreserved,omitempty"`

	// Merge consecutive slashes (e.g., /api//users -> /api/users).
	// Default: true when enabled
	MergeSlashes *bool `json:"merge_slashes,omitempty" yaml:"merge_slashes,omitempty"`

	// Lowercase scheme and host components.
	// Default: true when enabled
	LowercaseSchemeHost *bool `json:"lowercase_scheme_host,omitempty" yaml:"lowercase_scheme_host,omitempty"`
}

// RateLimitHeaderConfig controls standardized rate limit response headers
// (draft-ietf-httpapi-ratelimit-headers)
type RateLimitHeaderConfig struct {
	// Enable standardized rate limit headers (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset).
	// Default: false
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`
}

// HTTPPriorityConfig controls HTTP Priority header handling (RFC 9218)
type HTTPPriorityConfig struct {
	// Forward the Priority header to upstream origins.
	// Default: false
	ForwardPriority bool `json:"forward_priority,omitempty" yaml:"forward_priority,omitempty"`
}

// ProblemDetailsConfig controls RFC 9457 error response format
type ProblemDetailsConfig struct {
	// Enable RFC 9457 application/problem+json error responses for proxy-generated errors.
	// Default: false
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`

	// Base URI for problem type URIs.
	// Default: "about:blank"
	BaseURI string `json:"base_uri,omitempty" yaml:"base_uri,omitempty"`
}

// EarlyDataConfig controls RFC 8470 early data handling
type EarlyDataConfig struct {
	// Reject non-idempotent requests received via TLS 0-RTT early data with 425 Too Early.
	// Default: false (early data requests are forwarded normally)
	RejectNonIdempotent bool `json:"reject_non_idempotent,omitempty" yaml:"reject_non_idempotent,omitempty"`

	// Forward the Early-Data: 1 header to upstream when request was received in early data.
	// Default: false
	ForwardHeader bool `json:"forward_header,omitempty" yaml:"forward_header,omitempty"`

	// Methods considered safe for early data (idempotent methods).
	// Default: ["GET", "HEAD", "OPTIONS"]
	SafeMethods []string `json:"safe_methods,omitempty" yaml:"safe_methods,omitempty"`
}

// ExpectContinueConfig controls Expect: 100-continue handling (RFC 9110 Section 10.1.1)
type ExpectContinueConfig struct {
	// Mode for handling Expect: 100-continue.
	// "forward" - forward to upstream and relay response
	// "absorb"  - handle locally, always send 100 Continue
	// "strip"   - remove Expect header before forwarding
	// Default: "forward"
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
}

// RangeRequestConfig controls Range request handling (RFC 7233)
type RangeRequestConfig struct {
	// Enable range request pass-through to upstream.
	// Default: true (range requests are forwarded)
	DisablePassthrough bool `json:"disable_passthrough,omitempty" yaml:"disable_passthrough,omitempty"`

	// Advertise range support via Accept-Ranges header.
	// Default: false (let upstream handle Accept-Ranges)
	AdvertiseRanges bool `json:"advertise_ranges,omitempty" yaml:"advertise_ranges,omitempty"`
}

// TrailerType defines the type of generated trailer
type TrailerType string

const (
	// TrailerChecksum is a constant for trailer checksum.
	TrailerChecksum TrailerType = "checksum"
	// TrailerTiming is a constant for trailer timing.
	TrailerTiming TrailerType = "timing"
	// TrailerCustom is a constant for trailer custom.
	TrailerCustom TrailerType = "custom"
)
