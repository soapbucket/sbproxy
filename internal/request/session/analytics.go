// Package session provides session management with cookie-based tracking and storage backends.
package session

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	sessionAnalyticsDurationHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_session_analytics_duration_seconds",
		Help:    "Session analytics duration in seconds",
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"origin"})

	sessionAnalyticsPageViewsHist = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_session_analytics_page_views",
		Help:    "Number of page views per session",
		Buckets: []float64{1, 2, 3, 5, 10, 20, 50, 100},
	}, []string{"origin"})

	sessionAnalyticsConversionsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_session_analytics_conversions_total",
		Help: "Session conversion events",
	}, []string{"origin", "event"})

	sessionAnalyticsActiveGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_session_analytics_active",
		Help: "Number of currently active sessions tracked by analytics",
	}, []string{"origin"})
)

const (
	defaultSessionTimeout = 30 * time.Minute
	defaultMaxFlowDepth   = 100
	flowSeparator         = " > "
)

// AnalyticsConfig configures session analytics.
type AnalyticsConfig struct {
	Enabled          bool          `json:"enabled,omitempty"`
	TrackPageFlow    bool          `json:"track_page_flow,omitempty"`   // Track page navigation paths
	TrackConversions bool          `json:"track_conversions,omitempty"` // Track conversion events
	ConversionPaths  []string      `json:"conversion_paths,omitempty"` // URL paths that count as conversions
	SessionTimeout   time.Duration `json:"session_timeout,omitempty"`  // Inactivity timeout (default: 30m)
	MaxFlowDepth     int           `json:"max_flow_depth,omitempty"`   // Max pages to track per session (default: 100)
}

// SessionAnalytics tracks session-level analytics.
type SessionAnalytics struct {
	config   AnalyticsConfig
	mu       sync.RWMutex
	sessions map[string]*sessionRecord

	// Global metrics
	totalSessions    atomic.Int64
	totalPageViews   atomic.Int64
	totalConversions atomic.Int64
}

type sessionRecord struct {
	sessionID   string
	origin      string
	startedAt   time.Time
	lastSeen    time.Time
	pageViews   int
	pages       []pageView // Page flow
	conversions []string   // Conversion events
	isActive    bool
}

type pageView struct {
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
	Referrer  string    `json:"referrer,omitempty"`
}

// SessionFlowStats holds aggregated page flow statistics.
type SessionFlowStats struct {
	TotalSessions  int64         `json:"total_sessions"`
	ActiveSessions int64         `json:"active_sessions"`
	AvgDuration    time.Duration `json:"avg_duration"`
	AvgPageViews   float64       `json:"avg_page_views"`
	TopPaths       []PathCount   `json:"top_paths"`
	TopFlows       []FlowCount   `json:"top_flows"`
	ConversionRate float64       `json:"conversion_rate"`
}

// PathCount holds a path and its visit count.
type PathCount struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// FlowCount holds a navigation flow and its occurrence count.
type FlowCount struct {
	Flow  string `json:"flow"` // e.g., "/ > /products > /cart > /checkout"
	Count int64  `json:"count"`
}

// NewSessionAnalytics creates a new SessionAnalytics instance.
func NewSessionAnalytics(config AnalyticsConfig) *SessionAnalytics {
	if config.SessionTimeout == 0 {
		config.SessionTimeout = defaultSessionTimeout
	}
	if config.MaxFlowDepth == 0 {
		config.MaxFlowDepth = defaultMaxFlowDepth
	}

	return &SessionAnalytics{
		config:   config,
		sessions: make(map[string]*sessionRecord),
	}
}

// RecordPageView tracks a page view for the given session.
// Creates a new session record if one does not exist.
func (sa *SessionAnalytics) RecordPageView(sessionID, origin, path, referrer string) {
	if !sa.config.Enabled {
		return
	}

	sa.mu.Lock()
	defer sa.mu.Unlock()

	now := time.Now()

	record, exists := sa.sessions[sessionID]
	if !exists {
		record = &sessionRecord{
			sessionID: sessionID,
			origin:    origin,
			startedAt: now,
			lastSeen:  now,
			isActive:  true,
			pages:     make([]pageView, 0, 8),
		}
		sa.sessions[sessionID] = record
		sa.totalSessions.Add(1)
		sessionAnalyticsActiveGauge.WithLabelValues(origin).Inc()
	}

	record.lastSeen = now
	record.pageViews++
	sa.totalPageViews.Add(1)

	// Track page flow if enabled and within depth limit
	if sa.config.TrackPageFlow && len(record.pages) < sa.config.MaxFlowDepth {
		record.pages = append(record.pages, pageView{
			Path:      path,
			Timestamp: now,
			Referrer:  referrer,
		})
	}

	// Check if this path is a conversion path
	if sa.config.TrackConversions && sa.isConversionPath(path) {
		sa.recordConversionLocked(record, origin, "page:"+path)
	}
}

// RecordConversion tracks a conversion event for the given session.
func (sa *SessionAnalytics) RecordConversion(sessionID, origin, event string) {
	if !sa.config.Enabled || !sa.config.TrackConversions {
		return
	}

	sa.mu.Lock()
	defer sa.mu.Unlock()

	record, exists := sa.sessions[sessionID]
	if !exists {
		// Create a minimal record for tracking the conversion
		record = &sessionRecord{
			sessionID: sessionID,
			origin:    origin,
			startedAt: time.Now(),
			lastSeen:  time.Now(),
			isActive:  true,
			pages:     make([]pageView, 0),
		}
		sa.sessions[sessionID] = record
		sa.totalSessions.Add(1)
		sessionAnalyticsActiveGauge.WithLabelValues(origin).Inc()
	}

	sa.recordConversionLocked(record, origin, event)
}

// recordConversionLocked records a conversion. Caller must hold sa.mu.
func (sa *SessionAnalytics) recordConversionLocked(record *sessionRecord, origin, event string) {
	record.conversions = append(record.conversions, event)
	sa.totalConversions.Add(1)
	sessionAnalyticsConversionsCounter.WithLabelValues(origin, event).Inc()
}

// EndSession finalizes a session and emits its metrics.
func (sa *SessionAnalytics) EndSession(sessionID, origin string) {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	record, exists := sa.sessions[sessionID]
	if !exists {
		return
	}

	sa.finalizeRecordLocked(record)
	delete(sa.sessions, sessionID)
}

// finalizeRecordLocked emits metrics for a completed session. Caller must hold sa.mu.
func (sa *SessionAnalytics) finalizeRecordLocked(record *sessionRecord) {
	if !record.isActive {
		return
	}

	record.isActive = false
	duration := record.lastSeen.Sub(record.startedAt).Seconds()

	sessionAnalyticsDurationHist.WithLabelValues(record.origin).Observe(duration)
	sessionAnalyticsPageViewsHist.WithLabelValues(record.origin).Observe(float64(record.pageViews))
	sessionAnalyticsActiveGauge.WithLabelValues(record.origin).Dec()
}

// CleanupExpired removes timed-out sessions and emits their final metrics.
func (sa *SessionAnalytics) CleanupExpired() {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	now := time.Now()
	var expired []string

	for id, record := range sa.sessions {
		if now.Sub(record.lastSeen) >= sa.config.SessionTimeout {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		record := sa.sessions[id]
		sa.finalizeRecordLocked(record)
		delete(sa.sessions, id)
	}
}

// Stats returns aggregated statistics, optionally filtered by origin.
// Pass an empty string for origin to get stats across all origins.
func (sa *SessionAnalytics) Stats(origin string) *SessionFlowStats {
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	stats := &SessionFlowStats{}
	pathCounts := make(map[string]int64)
	flowCounts := make(map[string]int64)

	var totalDuration time.Duration
	var totalPageViews int64
	var sessionsWithConversions int64
	var matchedSessions int64

	for _, record := range sa.sessions {
		if origin != "" && record.origin != origin {
			continue
		}

		matchedSessions++

		if record.isActive {
			stats.ActiveSessions++
		}

		duration := record.lastSeen.Sub(record.startedAt)
		totalDuration += duration
		totalPageViews += int64(record.pageViews)

		if len(record.conversions) > 0 {
			sessionsWithConversions++
		}

		// Aggregate path counts
		for _, pv := range record.pages {
			pathCounts[pv.Path]++
		}

		// Build flow string for this session
		if len(record.pages) > 1 {
			flow := sa.buildFlowString(record.pages)
			flowCounts[flow]++
		}
	}

	stats.TotalSessions = matchedSessions

	if matchedSessions > 0 {
		stats.AvgDuration = totalDuration / time.Duration(matchedSessions)
		stats.AvgPageViews = float64(totalPageViews) / float64(matchedSessions)
		stats.ConversionRate = float64(sessionsWithConversions) / float64(matchedSessions)
	}

	stats.TopPaths = sa.topPaths(pathCounts, 10)
	stats.TopFlows = sa.topFlows(flowCounts, 10)

	return stats
}

// isConversionPath checks if the path matches any configured conversion path.
func (sa *SessionAnalytics) isConversionPath(path string) bool {
	for _, cp := range sa.config.ConversionPaths {
		if cp == path {
			return true
		}
		// Support prefix matching with trailing wildcard
		if strings.HasSuffix(cp, "*") {
			prefix := strings.TrimSuffix(cp, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}
	return false
}

// buildFlowString creates a flow string from page views (e.g., "/ > /products > /cart").
func (sa *SessionAnalytics) buildFlowString(pages []pageView) string {
	if len(pages) == 0 {
		return ""
	}

	var b strings.Builder
	for i, pv := range pages {
		if i > 0 {
			b.WriteString(flowSeparator)
		}
		b.WriteString(pv.Path)
	}
	return b.String()
}

// topPaths returns the top N most visited paths sorted by count descending.
func (sa *SessionAnalytics) topPaths(counts map[string]int64, n int) []PathCount {
	result := make([]PathCount, 0, len(counts))
	for path, count := range counts {
		result = append(result, PathCount{Path: path, Count: count})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	if len(result) > n {
		result = result[:n]
	}
	return result
}

// topFlows returns the top N most common flows sorted by count descending.
func (sa *SessionAnalytics) topFlows(counts map[string]int64, n int) []FlowCount {
	result := make([]FlowCount, 0, len(counts))
	for flow, count := range counts {
		result = append(result, FlowCount{Flow: flow, Count: count})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	if len(result) > n {
		result = result[:n]
	}
	return result
}
