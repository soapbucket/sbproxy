package session

import (
	"testing"
	"time"
)

func TestSessionAnalytics_RecordPageView(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:       true,
		TrackPageFlow: true,
		MaxFlowDepth:  100,
	})

	sa.RecordPageView("sess-1", "origin-a", "/", "")
	sa.RecordPageView("sess-1", "origin-a", "/products", "/")
	sa.RecordPageView("sess-1", "origin-a", "/products/123", "/products")

	sa.mu.RLock()
	record, exists := sa.sessions["sess-1"]
	sa.mu.RUnlock()

	if !exists {
		t.Fatal("expected session record to exist")
	}

	if record.pageViews != 3 {
		t.Errorf("expected 3 page views, got %d", record.pageViews)
	}

	if len(record.pages) != 3 {
		t.Errorf("expected 3 pages in flow, got %d", len(record.pages))
	}

	if record.pages[0].Path != "/" {
		t.Errorf("expected first page '/', got '%s'", record.pages[0].Path)
	}

	if record.pages[1].Referrer != "/" {
		t.Errorf("expected referrer '/', got '%s'", record.pages[1].Referrer)
	}

	if sa.totalPageViews.Load() != 3 {
		t.Errorf("expected total page views 3, got %d", sa.totalPageViews.Load())
	}

	if sa.totalSessions.Load() != 1 {
		t.Errorf("expected total sessions 1, got %d", sa.totalSessions.Load())
	}
}

func TestSessionAnalytics_RecordPageView_Disabled(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled: false,
	})

	sa.RecordPageView("sess-1", "origin-a", "/", "")

	sa.mu.RLock()
	count := len(sa.sessions)
	sa.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected no sessions when disabled, got %d", count)
	}
}

func TestSessionAnalytics_RecordConversion(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:          true,
		TrackConversions: true,
	})

	// Record a page view first to create the session
	sa.RecordPageView("sess-1", "origin-a", "/", "")

	// Record a conversion
	sa.RecordConversion("sess-1", "origin-a", "purchase")

	sa.mu.RLock()
	record := sa.sessions["sess-1"]
	sa.mu.RUnlock()

	if len(record.conversions) != 1 {
		t.Errorf("expected 1 conversion, got %d", len(record.conversions))
	}

	if record.conversions[0] != "purchase" {
		t.Errorf("expected conversion 'purchase', got '%s'", record.conversions[0])
	}

	if sa.totalConversions.Load() != 1 {
		t.Errorf("expected total conversions 1, got %d", sa.totalConversions.Load())
	}
}

func TestSessionAnalytics_RecordConversion_AutoConversionPath(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:          true,
		TrackPageFlow:    true,
		TrackConversions: true,
		ConversionPaths:  []string{"/checkout", "/signup*"},
	})

	sa.RecordPageView("sess-1", "origin-a", "/", "")
	sa.RecordPageView("sess-1", "origin-a", "/checkout", "/")

	sa.mu.RLock()
	record := sa.sessions["sess-1"]
	sa.mu.RUnlock()

	if len(record.conversions) != 1 {
		t.Errorf("expected 1 auto-conversion, got %d", len(record.conversions))
	}

	if record.conversions[0] != "page:/checkout" {
		t.Errorf("expected conversion 'page:/checkout', got '%s'", record.conversions[0])
	}
}

func TestSessionAnalytics_RecordConversion_WildcardPath(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:          true,
		TrackPageFlow:    true,
		TrackConversions: true,
		ConversionPaths:  []string{"/api/purchase*"},
	})

	sa.RecordPageView("sess-1", "origin-a", "/api/purchase/complete", "")

	sa.mu.RLock()
	record := sa.sessions["sess-1"]
	sa.mu.RUnlock()

	if len(record.conversions) != 1 {
		t.Errorf("expected 1 wildcard conversion, got %d", len(record.conversions))
	}
}

func TestSessionAnalytics_CleanupExpired(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:        true,
		TrackPageFlow:  true,
		SessionTimeout: 100 * time.Millisecond,
	})

	// Record page views for two sessions
	sa.RecordPageView("sess-1", "origin-a", "/", "")
	sa.RecordPageView("sess-2", "origin-a", "/about", "")

	// Wait for sessions to expire
	time.Sleep(150 * time.Millisecond)

	// Record a fresh session so it does not expire
	sa.RecordPageView("sess-3", "origin-a", "/contact", "")

	sa.CleanupExpired()

	sa.mu.RLock()
	count := len(sa.sessions)
	_, sess1Exists := sa.sessions["sess-1"]
	_, sess2Exists := sa.sessions["sess-2"]
	_, sess3Exists := sa.sessions["sess-3"]
	sa.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 session after cleanup, got %d", count)
	}

	if sess1Exists {
		t.Error("expected sess-1 to be cleaned up")
	}

	if sess2Exists {
		t.Error("expected sess-2 to be cleaned up")
	}

	if !sess3Exists {
		t.Error("expected sess-3 to still exist")
	}
}

func TestSessionAnalytics_Stats(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:          true,
		TrackPageFlow:    true,
		TrackConversions: true,
		ConversionPaths:  []string{"/checkout"},
	})

	// Session 1: browses and converts
	sa.RecordPageView("sess-1", "origin-a", "/", "")
	sa.RecordPageView("sess-1", "origin-a", "/products", "/")
	sa.RecordPageView("sess-1", "origin-a", "/checkout", "/products")

	// Session 2: browses only
	sa.RecordPageView("sess-2", "origin-a", "/", "")
	sa.RecordPageView("sess-2", "origin-a", "/about", "/")

	// Session 3: different origin
	sa.RecordPageView("sess-3", "origin-b", "/", "")

	// Stats for origin-a
	stats := sa.Stats("origin-a")

	if stats.TotalSessions != 2 {
		t.Errorf("expected 2 sessions for origin-a, got %d", stats.TotalSessions)
	}

	if stats.ActiveSessions != 2 {
		t.Errorf("expected 2 active sessions, got %d", stats.ActiveSessions)
	}

	// Average page views: (3 + 2) / 2 = 2.5
	if stats.AvgPageViews != 2.5 {
		t.Errorf("expected avg page views 2.5, got %f", stats.AvgPageViews)
	}

	// Conversion rate: 1 out of 2 sessions = 0.5
	if stats.ConversionRate != 0.5 {
		t.Errorf("expected conversion rate 0.5, got %f", stats.ConversionRate)
	}

	// Stats for all origins
	allStats := sa.Stats("")

	if allStats.TotalSessions != 3 {
		t.Errorf("expected 3 total sessions, got %d", allStats.TotalSessions)
	}
}

func TestSessionAnalytics_TopPaths(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:       true,
		TrackPageFlow: true,
	})

	// Multiple sessions visiting different pages
	sa.RecordPageView("sess-1", "origin-a", "/", "")
	sa.RecordPageView("sess-1", "origin-a", "/products", "/")
	sa.RecordPageView("sess-2", "origin-a", "/", "")
	sa.RecordPageView("sess-2", "origin-a", "/products", "/")
	sa.RecordPageView("sess-2", "origin-a", "/about", "/products")
	sa.RecordPageView("sess-3", "origin-a", "/", "")

	stats := sa.Stats("origin-a")

	if len(stats.TopPaths) == 0 {
		t.Fatal("expected top paths to be non-empty")
	}

	// "/" should be the most visited path (3 visits)
	if stats.TopPaths[0].Path != "/" {
		t.Errorf("expected top path '/', got '%s'", stats.TopPaths[0].Path)
	}

	if stats.TopPaths[0].Count != 3 {
		t.Errorf("expected top path count 3, got %d", stats.TopPaths[0].Count)
	}

	// "/products" should be second (2 visits)
	if len(stats.TopPaths) < 2 {
		t.Fatal("expected at least 2 top paths")
	}

	if stats.TopPaths[1].Path != "/products" {
		t.Errorf("expected second path '/products', got '%s'", stats.TopPaths[1].Path)
	}

	if stats.TopPaths[1].Count != 2 {
		t.Errorf("expected second path count 2, got %d", stats.TopPaths[1].Count)
	}
}

func TestSessionAnalytics_EndSession(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:       true,
		TrackPageFlow: true,
	})

	sa.RecordPageView("sess-1", "origin-a", "/", "")
	sa.RecordPageView("sess-1", "origin-a", "/products", "/")

	sa.EndSession("sess-1", "origin-a")

	sa.mu.RLock()
	_, exists := sa.sessions["sess-1"]
	sa.mu.RUnlock()

	if exists {
		t.Error("expected session to be removed after EndSession")
	}
}

func TestSessionAnalytics_MaxFlowDepth(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:       true,
		TrackPageFlow: true,
		MaxFlowDepth:  3,
	})

	sa.RecordPageView("sess-1", "origin-a", "/page1", "")
	sa.RecordPageView("sess-1", "origin-a", "/page2", "/page1")
	sa.RecordPageView("sess-1", "origin-a", "/page3", "/page2")
	sa.RecordPageView("sess-1", "origin-a", "/page4", "/page3") // Should not be tracked

	sa.mu.RLock()
	record := sa.sessions["sess-1"]
	sa.mu.RUnlock()

	if record.pageViews != 4 {
		t.Errorf("expected 4 page views counted, got %d", record.pageViews)
	}

	if len(record.pages) != 3 {
		t.Errorf("expected 3 pages in flow (max depth), got %d", len(record.pages))
	}
}

func TestSessionAnalytics_DefaultConfig(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled: true,
	})

	if sa.config.SessionTimeout != defaultSessionTimeout {
		t.Errorf("expected default session timeout %v, got %v", defaultSessionTimeout, sa.config.SessionTimeout)
	}

	if sa.config.MaxFlowDepth != defaultMaxFlowDepth {
		t.Errorf("expected default max flow depth %d, got %d", defaultMaxFlowDepth, sa.config.MaxFlowDepth)
	}
}

func TestSessionAnalytics_IsConversionPath(t *testing.T) {
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:         true,
		ConversionPaths: []string{"/checkout", "/signup*", "/api/purchase"},
	})

	tests := []struct {
		path string
		want bool
	}{
		{"/checkout", true},
		{"/signup", true},
		{"/signup/complete", true},
		{"/api/purchase", true},
		{"/products", false},
		{"/", false},
		{"/checkouts", false}, // Exact match, not prefix
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := sa.isConversionPath(tt.path)
			if got != tt.want {
				t.Errorf("isConversionPath(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
