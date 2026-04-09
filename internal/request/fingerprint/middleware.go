// Package fingerprint generates TLS and HTTP fingerprints (JA3, JA4) for client identification.
package fingerprint

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// FingerprintMiddleware returns HTTP middleware for fingerprint.
func FingerprintMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var duration time.Duration
		// Check for TCP/HTTP1/HTTP2 connection timing
		if timing := GetConnectionTimingFromContext(r.Context()); timing != nil {
			duration = timing.Duration()
			slog.Debug("TCP/HTTP1/HTTP2 connection timing found", "duration", duration.String())
		} else if quicTiming := GetQUICConnectionTimingFromContext(r.Context()); quicTiming != nil {
			// For QUIC/HTTP3 connections, mark the first byte when request arrives
			connectedAt := quicTiming.GetConnectedAt()
			firstByteAtBefore := quicTiming.GetFirstByteAt()
			slog.Debug("QUIC timing before MarkFirstByte", "connected_at", connectedAt, "first_byte_at", firstByteAtBefore, "first_byte_is_zero", firstByteAtBefore.IsZero())

			quicTiming.MarkFirstByte()

			firstByteAtAfter := quicTiming.GetFirstByteAt()
			duration = quicTiming.Duration()
			slog.Debug("QUIC timing after MarkFirstByte", "first_byte_at", firstByteAtAfter, "duration", duration.String(), "duration_ns", duration.Nanoseconds())
		} else {
			slog.Debug("No connection timing found in context")
		}

		fp := GenerateFingerprint(r, duration)

		requestData := reqctx.GetRequestData(r.Context())
		if requestData != nil {
			requestData.Fingerprint = &reqctx.Fingerprint{
				Hash:          fp.Hash,
				Composite:     fp.Composite,
				IPHash:        fp.IPHash,
				UserAgentHash: fp.UserAgentHash,
				HeaderPattern: fp.HeaderPattern,
				TLSHash:       fp.TLSHash,
				CookieCount:   fp.CookieCount,
				Version:       FingerprintVersion,
				ConnDuration:  fp.ConnDuration,
			}
		}

		r.Header.Set(httputil.HeaderXSbFingerprint, fp.Hash)
		requestData.AddDebugHeader(httputil.HeaderXSbFingerprintDebug, fp.Composite+":"+fp.ConnDuration.String())
		next.ServeHTTP(w, r)
	})
}
