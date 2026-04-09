// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"encoding/binary"
	"net/http"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
)

// cache key for transport reuse
type transportKey struct {
	idleConnTimeout       time.Duration
	tlsHandshakeTimeout   time.Duration
	dialTimeout           time.Duration
	keepAlive             time.Duration
	skipTLSVerifyHost     bool
	minTLSVersion         string
	http11Only            bool
	maxIdleConns          int
	maxIdleConnsPerHost   int
	maxConnsPerHost       int
	respHeaderTimeout     time.Duration
	expectContinueTimeout time.Duration
	disableCompression    bool
	disableKeepAlives     bool
	writeBufferSize       int
	readBufferSize        int
	forceAttemptHTTP2    bool
	enableHTTP3           bool
	// mTLS configuration
	mtlsClientCertFile string
	mtlsClientKeyFile  string
	mtlsCACertFile     string
	mtlsClientCertData string
	mtlsClientKeyData  string
	mtlsCACertData     string
}

// hash computes an xxhash digest over all fields, avoiding byte-by-byte
// comparison of potentially large PEM cert data on every sync.Map lookup.
func (k transportKey) hash() uint64 {
	h := xxhash.New()
	var buf [8]byte

	writeDuration := func(d time.Duration) {
		binary.LittleEndian.PutUint64(buf[:], uint64(d))
		_, _ = h.Write(buf[:])
	}
	writeInt := func(v int) {
		binary.LittleEndian.PutUint64(buf[:], uint64(v))
		_, _ = h.Write(buf[:])
	}
	writeBool := func(v bool) {
		if v {
			buf[0] = 1
		} else {
			buf[0] = 0
		}
		_, _ = h.Write(buf[:1])
	}
	writeString := func(s string) {
		_, _ = h.WriteString(s)
		_, _ = h.Write([]byte{0}) // separator
	}

	writeDuration(k.idleConnTimeout)
	writeDuration(k.tlsHandshakeTimeout)
	writeDuration(k.dialTimeout)
	writeDuration(k.keepAlive)
	writeBool(k.skipTLSVerifyHost)
	writeString(k.minTLSVersion)
	writeBool(k.http11Only)
	writeInt(k.maxIdleConns)
	writeInt(k.maxIdleConnsPerHost)
	writeInt(k.maxConnsPerHost)
	writeDuration(k.respHeaderTimeout)
	writeDuration(k.expectContinueTimeout)
	writeBool(k.disableCompression)
	writeBool(k.disableKeepAlives)
	writeInt(k.writeBufferSize)
	writeInt(k.readBufferSize)
	writeBool(k.forceAttemptHTTP2)
	writeBool(k.enableHTTP3)
	writeString(k.mtlsClientCertFile)
	writeString(k.mtlsClientKeyFile)
	writeString(k.mtlsCACertFile)
	writeString(k.mtlsClientCertData)
	writeString(k.mtlsClientKeyData)
	writeString(k.mtlsCACertData)

	return h.Sum64()
}

// transportCacheEntry stores both the hash key and full key for collision handling
type transportCacheEntry struct {
	key       transportKey
	transport http.RoundTripper
}

var transportCache sync.Map // map[uint64]*transportCacheEntry

func getOrCreateTransport(config httputil.HTTPClientConfig) http.RoundTripper {
	key := transportKey{
		idleConnTimeout:       config.IdleConnTimeout,
		tlsHandshakeTimeout:   config.TLSHandshakeTimeout,
		dialTimeout:           config.DialTimeout,
		keepAlive:             config.KeepAlive,
		skipTLSVerifyHost:     config.SkipTLSVerifyHost,
		minTLSVersion:         config.MinTLSVersion,
		http11Only:            config.HTTP11Only,
		maxIdleConns:          config.MaxIdleConns,
		maxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		maxConnsPerHost:       config.MaxConnsPerHost,
		respHeaderTimeout:     config.ResponseHeaderTimeout,
		expectContinueTimeout: config.ExpectContinueTimeout,
		disableCompression:    config.DisableCompression,
		disableKeepAlives:     config.DisableKeepAlives,
		writeBufferSize:       config.WriteBufferSize,
		readBufferSize:        config.ReadBufferSize,
		forceAttemptHTTP2:     config.ForceAttemptHTTP2,
		enableHTTP3:           config.EnableHTTP3,
		mtlsClientCertFile:    config.MTLSClientCertFile,
		mtlsClientKeyFile:     config.MTLSClientKeyFile,
		mtlsCACertFile:        config.MTLSCACertFile,
		mtlsClientCertData:    config.MTLSClientCertData,
		mtlsClientKeyData:     config.MTLSClientKeyData,
		mtlsCACertData:        config.MTLSCACertData,
	}

	h := key.hash()
	if entry, ok := transportCache.Load(h); ok {
		cached := entry.(*transportCacheEntry)
		if cached.key == key {
			return cached.transport
		}
	}

	client := httputil.NewHTTPClient(config)
	tr := client.Client.Transport
	entry := &transportCacheEntry{key: key, transport: tr}
	actual, _ := transportCache.LoadOrStore(h, entry)
	return actual.(*transportCacheEntry).transport
}

// NewHTTPTransport creates a new HTTP transport using the optimized configuration
func NewHTTPTransport(idleConnTimeout, tlsHandshakeTimeout, dialTimeout, keepAlive time.Duration, skipTLSVerifyHost, http11Only bool) http.RoundTripper {
	config := httputil.DefaultHTTPClientConfig()
	config.IdleConnTimeout = idleConnTimeout
	config.TLSHandshakeTimeout = tlsHandshakeTimeout
	config.DialTimeout = dialTimeout
	config.KeepAlive = keepAlive
	config.SkipTLSVerifyHost = skipTLSVerifyHost
	config.MinTLSVersion = ""
	config.HTTP11Only = http11Only

	return getOrCreateTransport(config)
}

// NewHTTPTransportWithHTTP3 creates a new HTTP transport with optional HTTP/3 support
func NewHTTPTransportWithHTTP3(idleConnTimeout, tlsHandshakeTimeout, dialTimeout, keepAlive time.Duration, skipTLSVerifyHost, http11Only, enableHTTP3 bool) http.RoundTripper {
	config := httputil.DefaultHTTPClientConfig()
	config.IdleConnTimeout = idleConnTimeout
	config.TLSHandshakeTimeout = tlsHandshakeTimeout
	config.DialTimeout = dialTimeout
	config.KeepAlive = keepAlive
	config.SkipTLSVerifyHost = skipTLSVerifyHost
	config.MinTLSVersion = ""
	config.HTTP11Only = http11Only
	config.EnableHTTP3 = enableHTTP3

	return getOrCreateTransport(config)
}

// NewHTTPTransportWithOptions creates a transport using defaults, overridden by provided options
func NewHTTPTransportWithOptions(idleConnTimeout, tlsHandshakeTimeout, dialTimeout, keepAlive time.Duration, skipTLSVerifyHost, http11Only bool, opts *httputil.HTTPTransportOptions) http.RoundTripper {
	config := httputil.DefaultHTTPClientConfig()
	config.IdleConnTimeout = idleConnTimeout
	config.TLSHandshakeTimeout = tlsHandshakeTimeout
	config.DialTimeout = dialTimeout
	config.KeepAlive = keepAlive
	config.SkipTLSVerifyHost = skipTLSVerifyHost
	config.MinTLSVersion = ""
	config.HTTP11Only = http11Only

	// Apply option overrides if provided
	if opts != nil {
		if opts.MaxIdleConns > 0 {
			config.MaxIdleConns = opts.MaxIdleConns
		}
		if opts.MaxIdleConnsPerHost > 0 {
			config.MaxIdleConnsPerHost = opts.MaxIdleConnsPerHost
		}
		if opts.MaxConnsPerHost >= 0 {
			config.MaxConnsPerHost = opts.MaxConnsPerHost
		}
		if opts.ResponseHeaderTimeout > 0 {
			config.ResponseHeaderTimeout = opts.ResponseHeaderTimeout
		}
		if opts.ExpectContinueTimeout > 0 {
			config.ExpectContinueTimeout = opts.ExpectContinueTimeout
		}
		config.DisableCompression = opts.DisableCompression
		config.DisableKeepAlives = opts.DisableKeepAlives
		if opts.WriteBufferSize > 0 {
			config.WriteBufferSize = opts.WriteBufferSize
		}
		if opts.ReadBufferSize > 0 {
			config.ReadBufferSize = opts.ReadBufferSize
		}
		if opts.ForceAttemptHTTP2 != nil {
			config.ForceAttemptHTTP2 = *opts.ForceAttemptHTTP2
		}
		if opts.EnableHTTP3 != nil {
			config.EnableHTTP3 = *opts.EnableHTTP3
		}
		if opts.MinTLSVersion != "" {
			config.MinTLSVersion = opts.MinTLSVersion
		}
		// Apply mTLS configuration if provided
		if opts.MTLSClientCertFile != "" {
			config.MTLSClientCertFile = opts.MTLSClientCertFile
		}
		if opts.MTLSClientKeyFile != "" {
			config.MTLSClientKeyFile = opts.MTLSClientKeyFile
		}
		if opts.MTLSCACertFile != "" {
			config.MTLSCACertFile = opts.MTLSCACertFile
		}
		if opts.MTLSClientCertData != "" {
			config.MTLSClientCertData = opts.MTLSClientCertData
		}
		if opts.MTLSClientKeyData != "" {
			config.MTLSClientKeyData = opts.MTLSClientKeyData
		}
		if opts.MTLSCACertData != "" {
			config.MTLSCACertData = opts.MTLSCACertData
		}
	}

	return getOrCreateTransport(config)
}
