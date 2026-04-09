package plugin

// Observer provides an abstraction for metrics collection that decouples the proxy
// core from any specific metrics backend (Prometheus, StatsD, OpenTelemetry, etc.).
// The proxy engine and plugins record metrics through this interface without knowing
// which backend will store them.
//
// [NoopObserver] is used by default, discarding all metrics. Register a real
// implementation (e.g., Prometheus) at startup via the proxy options.
//
// All methods return pre-registered handles that should be stored and reused. The
// handle pattern avoids map lookups and allocations on every metric recording call,
// making it suitable for hot paths like per-request instrumentation.
type Observer interface {
	// Counter returns a handle for a monotonically increasing counter metric.
	// The labelNames define the dimensions of the metric (e.g., "method", "status").
	Counter(name string, labelNames ...string) CounterHandle

	// Histogram returns a handle for a distribution metric that records observations
	// like request durations or response sizes. The labelNames define dimensions.
	Histogram(name string, labelNames ...string) HistogramHandle

	// Gauge returns a handle for a metric that can increase or decrease, such as
	// the number of active connections or current memory usage.
	Gauge(name string, labelNames ...string) GaugeHandle
}

// CounterHandle is a pre-registered handle for recording counter increments.
// Store the handle at initialization time and call Inc on every event to avoid
// repeated metric lookups.
type CounterHandle interface {
	// Inc increments the counter by 1 for the given label values. The label values
	// must match the labelNames provided when the handle was created, in the same order.
	Inc(labelValues ...string)
}

// HistogramHandle is a pre-registered handle for recording distribution observations.
// Store the handle at initialization time and call Observe per event.
type HistogramHandle interface {
	// Observe records a single observation (e.g., a request duration in seconds).
	// The label values must match the labelNames from handle creation.
	Observe(value float64, labelValues ...string)
}

// GaugeHandle is a pre-registered handle for recording gauge values that can go
// up and down. Store the handle at initialization time and call Set to update.
type GaugeHandle interface {
	// Set updates the gauge to the given value. The label values must match the
	// labelNames from handle creation.
	Set(value float64, labelValues ...string)
}

// NoopObserver returns an Observer where all operations silently discard data.
// This is the default observer used when no metrics backend is configured,
// ensuring that metric recording calls throughout the codebase are always safe
// to invoke without nil checks.
func NoopObserver() Observer { return &noopObserver{} }

type noopObserver struct{}

func (n *noopObserver) Counter(string, ...string) CounterHandle     { return noopCounter{} }
func (n *noopObserver) Histogram(string, ...string) HistogramHandle { return noopHistogram{} }
func (n *noopObserver) Gauge(string, ...string) GaugeHandle         { return noopGauge{} }

type noopCounter struct{}

func (noopCounter) Inc(...string) {}

type noopHistogram struct{}

func (noopHistogram) Observe(float64, ...string) {}

type noopGauge struct{}

func (noopGauge) Set(float64, ...string) {}
