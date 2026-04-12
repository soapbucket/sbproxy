// config.go defines the configuration struct for the gRPC action.
package grpc

import (
	pkgconfig "github.com/soapbucket/sbproxy/pkg/config"
	pkgtransport "github.com/soapbucket/sbproxy/pkg/transport"
)

// Config holds the full configuration for the grpc action.
type Config struct {
	// gRPC-specific fields
	URL           string `json:"url"`
	StripBasePath bool   `json:"strip_base_path,omitempty"`
	PreserveQuery bool   `json:"preserve_query,omitempty"`
	EnableGRPCWeb bool   `json:"enable_grpc_web,omitempty"`
	ForwardMetadata bool `json:"forward_metadata,omitempty"`

	MaxCallRecvMsgSize int `json:"max_call_recv_msg_size,omitempty"`
	MaxCallSendMsgSize int `json:"max_call_send_msg_size,omitempty"`

	// Connection settings (mirrors BaseConnection).
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

// connectionConfig converts the parsed Config into a public ConnectionConfig.
func (c *Config) connectionConfig() pkgtransport.ConnectionConfig {
	// gRPC requires HTTP/2; force off HTTP/1.1-only and HTTP/3.
	return pkgtransport.ConnectionConfig{
		SkipTLSVerifyHost:      c.SkipTLSVerifyHost,
		MinTLSVersion:          c.MinTLSVersion,
		HTTP11Only:             false, // gRPC requires HTTP/2
		EnableHTTP3:            false, // gRPC doesn't support HTTP/3
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
