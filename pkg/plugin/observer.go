package plugin

// Observer provides metrics collection.
type Observer interface {
	Counter(name string, labelNames ...string) CounterHandle
	Histogram(name string, labelNames ...string) HistogramHandle
	Gauge(name string, labelNames ...string) GaugeHandle
}

// CounterHandle is a monotonically increasing counter.
type CounterHandle interface {
	Inc(labelValues ...string)
}

// HistogramHandle records observations (e.g., request durations).
type HistogramHandle interface {
	Observe(value float64, labelValues ...string)
}

// GaugeHandle is a metric that can go up and down.
type GaugeHandle interface {
	Set(value float64, labelValues ...string)
}

// NoopObserver returns an Observer where all operations are no-ops.
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
