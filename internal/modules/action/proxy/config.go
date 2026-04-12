// config.go defines the configuration struct for the reverse proxy action.
package proxy

import (
	pkgconfig "github.com/soapbucket/sbproxy/pkg/config"
	pkgtransport "github.com/soapbucket/sbproxy/pkg/transport"
)

// Config holds the full configuration for the proxy action.
// Duration fields accept JSON strings like "30s", "5m", "1h".
type Config struct {
	// Proxy-specific fields
	URL           string `json:"url"`
	Method        string `json:"method,omitempty"`
	AltHostname   string `json:"alt_hostname,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	StripBasePath bool   `json:"strip_base_path,omitempty"`
	PreserveQuery bool   `json:"preserve_query,omitempty"`

	// Connection settings (mirrors BaseConnection).
	// Duration fields accept human-readable strings ("30s", "5m").
	SkipTLSVerifyHost      bool   `json:"skip_tls_verify_host,omitempty"`
	MinTLSVersion          string `json:"min_tls_version,omitempty"`
	HTTP11Only             bool   `json:"http11_only,omitempty"`
	EnableHTTP3            bool   `json:"enable_http3,omitempty"`
	DisableCompression     bool   `json:"disable_compression,omitempty"`
	DisableFollowRedirects bool   `json:"disable_follow_redirects,omitempty"`
	MaxRedirects           int    `json:"max_redirects,omitempty"`

	Timeout             pkgconfig.Duration `json:"timeout,omitempty"`
	Delay               pkgconfig.Duration `json:"delay,omitempty"`
	DialTimeout         pkgconfig.Duration `json:"dial_timeout,omitempty"`
	TLSHandshakeTimeout pkgconfig.Duration `json:"tls_handshake_timeout,omitempty"`
	IdleConnTimeout     pkgconfig.Duration `json:"idle_conn_timeout,omitempty"`
	KeepAlive           pkgconfig.Duration `json:"keep_alive,omitempty"`
	FlushInterval       pkgconfig.Duration `json:"flush_interval,omitempty"`

	ResponseHeaderTimeout pkgconfig.Duration `json:"response_header_timeout,omitempty"`
	ExpectContinueTimeout pkgconfig.Duration `json:"expect_continue_timeout,omitempty"`

	MaxConnections      int `json:"max_connections,omitempty"`
	MaxIdleConns        int `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`
	MaxConnsPerHost     int `json:"max_conns_per_host,omitempty"`

	WriteBufferSize int `json:"write_buffer_size,omitempty"`
	ReadBufferSize  int `json:"read_buffer_size,omitempty"`

	RateLimit  int `json:"rate_limit,omitempty"`
	BurstLimit int `json:"burst_limit,omitempty"`

	MTLSClientCertFile string `json:"mtls_client_cert_file,omitempty"`
	MTLSClientKeyFile  string `json:"mtls_client_key_file,omitempty"`
	MTLSCACertFile     string `json:"mtls_ca_cert_file,omitempty"`
	MTLSClientCertData string `json:"mtls_client_cert_data,omitempty"`
	MTLSClientKeyData  string `json:"mtls_client_key_data,omitempty"`
	MTLSCACertData     string `json:"mtls_ca_cert_data,omitempty"`
}

// connectionConfig converts the parsed Config into the public ConnectionConfig used
// by internal/engine/transport.NewTransportFromConfig.
func (c *Config) connectionConfig() pkgtransport.ConnectionConfig {
	return pkgtransport.ConnectionConfig{
		SkipTLSVerifyHost:      c.SkipTLSVerifyHost,
		MinTLSVersion:          c.MinTLSVersion,
		HTTP11Only:             c.HTTP11Only,
		EnableHTTP3:            c.EnableHTTP3,
		DisableCompression:     c.DisableCompression,
		DisableFollowRedirects: c.DisableFollowRedirects,
		MaxRedirects:           c.MaxRedirects,
		Timeout:                c.Timeout.Duration,
		Delay:                  c.Delay.Duration,
		DialTimeout:            c.DialTimeout.Duration,
		TLSHandshakeTimeout:    c.TLSHandshakeTimeout.Duration,
		IdleConnTimeout:        c.IdleConnTimeout.Duration,
		KeepAlive:              c.KeepAlive.Duration,
		FlushInterval:          c.FlushInterval.Duration,
		ResponseHeaderTimeout:  c.ResponseHeaderTimeout.Duration,
		ExpectContinueTimeout:  c.ExpectContinueTimeout.Duration,
		MaxConnections:         c.MaxConnections,
		MaxIdleConns:           c.MaxIdleConns,
		MaxIdleConnsPerHost:    c.MaxIdleConnsPerHost,
		MaxConnsPerHost:        c.MaxConnsPerHost,
		WriteBufferSize:        c.WriteBufferSize,
		ReadBufferSize:         c.ReadBufferSize,
		RateLimit:              c.RateLimit,
		BurstLimit:             c.BurstLimit,
		MTLSClientCertFile:     c.MTLSClientCertFile,
		MTLSClientKeyFile:      c.MTLSClientKeyFile,
		MTLSCACertFile:         c.MTLSCACertFile,
		MTLSClientCertData:     c.MTLSClientCertData,
		MTLSClientKeyData:      c.MTLSClientKeyData,
		MTLSCACertData:         c.MTLSCACertData,
	}
}
