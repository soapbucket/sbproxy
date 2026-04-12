// metric_lb.go registers Prometheus metrics for load balancer targets.
package metric

import "github.com/prometheus/client_golang/prometheus"

// Load Balancer Metrics

var (
	lbRequestsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_lb_requests_total",
		Help: "Total number of requests per load balancer target",
	}, []string{"origin_id", "target_url", "target_index"}))

	lbRequestDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_lb_request_duration_seconds",
		Help:    "Request duration for load balancer targets",
		Buckets: prometheus.DefBuckets,
	}, []string{"origin_id", "target_url", "target_index"}))

	lbRequestErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_lb_request_errors_total",
		Help: "Total number of errors per load balancer target",
	}, []string{"origin_id", "target_url", "target_index", "error_type"}))

	lbActiveConnections = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_lb_active_connections",
		Help: "Current number of active connections per target",
	}, []string{"origin_id", "target_url", "target_index"}))

	lbTargetHealth = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_lb_target_healthy",
		Help: "Health status of load balancer targets (1=healthy, 0=unhealthy)",
	}, []string{"origin_id", "target_url", "target_index"}))

	lbHealthCheckTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_lb_health_checks_total",
		Help: "Total number of health checks performed",
	}, []string{"origin_id", "target_url", "target_index", "result"}))

	lbTargetSelections = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_lb_target_selections_total",
		Help: "Total number of times each target was selected",
	}, []string{"origin_id", "target_url", "target_index", "selection_method"}))

	// Circuit Breaker Metrics
	lbCircuitBreakerState = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_lb_circuit_breaker_state",
		Help: "Current state of circuit breaker (0=closed, 1=half_open, 2=open)",
	}, []string{"origin_id", "target_url", "target_index"}))

	lbCircuitBreakerStateChanges = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_lb_circuit_breaker_state_changes_total",
		Help: "Total number of circuit breaker state changes",
	}, []string{"origin_id", "target_url", "target_index", "new_state"}))

	lbTargetDistribution = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_lb_target_distribution",
		Help:    "Request distribution across targets. Alert on uneven distribution.",
		Buckets: []float64{0, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
	}, []string{"origin", "target"}))
)

// Load Balancer Metric Functions

// LBRequestServed records a completed request to a load balancer target
func LBRequestServed(originID, targetURL, targetIndex string, duration float64) {
	lbRequestsTotal.WithLabelValues(originID, targetURL, targetIndex).Inc()
	lbRequestDuration.WithLabelValues(originID, targetURL, targetIndex).Observe(duration)
}

// LBRequestError records an error for a load balancer target
func LBRequestError(originID, targetURL, targetIndex, errorType string) {
	lbRequestErrors.WithLabelValues(originID, targetURL, targetIndex, errorType).Inc()
}

// LBActiveConnectionsSet sets the current number of active connections for a target
func LBActiveConnectionsSet(originID, targetURL, targetIndex string, count int64) {
	lbActiveConnections.WithLabelValues(originID, targetURL, targetIndex).Set(float64(count))
}

// LBTargetHealthSet sets the health status for a target (1=healthy, 0=unhealthy)
func LBTargetHealthSet(originID, targetURL, targetIndex string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	lbTargetHealth.WithLabelValues(originID, targetURL, targetIndex).Set(value)
}

// LBHealthCheckPerformed records a health check result
func LBHealthCheckPerformed(originID, targetURL, targetIndex, result string) {
	lbHealthCheckTotal.WithLabelValues(originID, targetURL, targetIndex, result).Inc()
}

// LBTargetSelected records when a target is selected for a request
func LBTargetSelected(originID, targetURL, targetIndex, selectionMethod string) {
	lbTargetSelections.WithLabelValues(originID, targetURL, targetIndex, selectionMethod).Inc()
}

// LBCircuitBreakerStateChanged records a circuit breaker state change
func LBCircuitBreakerStateChanged(originID, targetURL, targetIndex, newState string) {
	var stateValue float64
	switch newState {
	case "closed":
		stateValue = 0
	case "half_open":
		stateValue = 1
	case "open":
		stateValue = 2
	}
	lbCircuitBreakerState.WithLabelValues(originID, targetURL, targetIndex).Set(stateValue)
	lbCircuitBreakerStateChanges.WithLabelValues(originID, targetURL, targetIndex, newState).Inc()
}

// LBTargetDistribution records load balancer target distribution
func LBTargetDistribution(origin, target string, count float64) {
	lbTargetDistribution.WithLabelValues(origin, target).Observe(count)
}
