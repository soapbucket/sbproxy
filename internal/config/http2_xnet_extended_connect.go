package config

import "sync/atomic"
import _ "unsafe"

//go:linkname xnetHTTP2DisableExtendedConnectProtocol golang.org/x/net/http2.disableExtendedConnectProtocol
var xnetHTTP2DisableExtendedConnectProtocol bool

var http2ExtendedConnectRuntimeEnabled atomic.Bool

func enableHTTP2ExtendedConnectRuntime() {
	xnetHTTP2DisableExtendedConnectProtocol = false
	http2ExtendedConnectRuntimeEnabled.Store(true)
}

// HTTP2ExtendedConnectRuntimeEnabled reports whether any loaded config has requested
// RFC 8441 / extended CONNECT server support.
func HTTP2ExtendedConnectRuntimeEnabled() bool {
	return http2ExtendedConnectRuntimeEnabled.Load()
}
