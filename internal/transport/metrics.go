// metrics.go provides a metrics-recording decorator for http.RoundTripper.
package transport

import (
	"net/http"
	"strconv"
	"time"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// MetricsRoundTripper wraps an http.RoundTripper and records request duration
// and response status via a plugin.HistogramHandle. When recorder is nil, the
// wrapper is a zero-overhead passthrough.
type MetricsRoundTripper struct {
	next     http.RoundTripper
	recorder plugin.HistogramHandle
}

// NewMetricsRoundTripper creates a metrics-recording decorator around next.
// Pass a nil recorder to disable instrumentation entirely (zero overhead).
func NewMetricsRoundTripper(next http.RoundTripper, recorder plugin.HistogramHandle) *MetricsRoundTripper {
	return &MetricsRoundTripper{next: next, recorder: recorder}
}

// RoundTrip implements http.RoundTripper. When the recorder is nil, it
// delegates directly to the underlying transport with no timing overhead.
func (m *MetricsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.recorder == nil {
		return m.next.RoundTrip(req)
	}

	start := time.Now()
	resp, err := m.next.RoundTrip(req)
	elapsed := time.Since(start).Seconds()

	status := "0"
	if resp != nil {
		status = strconv.Itoa(resp.StatusCode)
	}
	m.recorder.Observe(elapsed, req.Method, status)

	return resp, err
}
