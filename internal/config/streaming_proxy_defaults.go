// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

// Default singleton configurations for proxy headers and streaming
// These are used when config fields are nil, providing intelligent defaults

var (
	defaultIncludeLegacyForwarded = true

	// DefaultProxyProtocol provides secure-by-default proxy protocol behavior
	DefaultProxyProtocol = &ProxyProtocolConfig{
		AllowTrace:              false,
		DisableRequestSmuggling: false,
		DisableMaxForwards:      false,
		DisableAutoDate:         false,
		InterimResponses: &InterimResponseConfig{
			Forward100Continue:  false,
			Forward103EarlyHints: false,
			ForwardOther:        false,
		},
	}

	// DefaultProxyHeaders provides standard proxy header behavior
	DefaultProxyHeaders = &ProxyHeaderConfig{
		TrustMode:      TrustAll,
		TrustedProxies: nil,
		TrustedHops:    0,
		XForwardedFor: &XForwardedForConfig{
			Mode: XFFAppend,
		},
		XForwardedProto: &XForwardedProtoConfig{
			Mode: XFPSet,
		},
		XForwardedHost: &XForwardedHostConfig{
			Mode: XFHSet,
		},
		XForwardedPort: &XForwardedPortConfig{
			Mode: XFPSet,
		},
		DisableXRealIP: false,
		Forwarded:      nil, // Not sent by default
		Via: &ViaHeaderConfig{
			Disable: false,
		},
		DisableServerHeaderRemoval: false,
		StripInternalHeaders:       nil,
		StripClientHeaders:         nil,
		AdditionalHopByHopHeaders:  nil,
		MaxRequestHeaderSize:       "1MB",
		MaxResponseHeaderSize:      "1MB",
		MaxHeaderCount:             100,
		PreserveHostHeader:         false,
		OverrideHost:               "",
		DisableHeaderNormalization: false,
	}

	// DefaultStreamingConfig provides standard streaming behavior
	DefaultStreamingConfig = &StreamingProxyConfig{
		DisableRequestChunking:        false,
		DisableResponseChunking:       false,
		ChunkThreshold:                "8KB",
		ChunkSize:                     "32KB",
		DisableTrailers:               false,
		DisableTrailerAnnouncement:    false,
		DisableTrailerForwarding:      false,
		GenerateTrailers:              nil,
		DisableSmallResponseBuffering: false,
		BufferSizeThreshold:           "64KB",
		ProxyBufferSize:               "32KB",
		DefaultFlushInterval:          "", // Empty = auto-detect
		ForceFlushHeaders:             false,
	}
)

