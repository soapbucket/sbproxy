package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalytics(t *testing.T) {
	a := NewAnalytics()

	a.RecordHit("semantic", 500, 1000)
	a.RecordHit("exact", 200, 500)
	a.RecordMiss()
	a.RecordMiss()

	stats := a.Stats()
	assert.Equal(t, int64(2), stats.Hits)
	assert.Equal(t, int64(2), stats.Misses)
	assert.Equal(t, int64(1), stats.SemanticHits)
	assert.Equal(t, int64(1), stats.ExactHits)
	assert.InDelta(t, 0.5, stats.HitRate, 0.001)
	assert.Equal(t, int64(4), stats.TotalRequests)
	assert.Equal(t, int64(700), stats.LatencySavedMs)
	assert.Equal(t, int64(1500), stats.CostSavedMicroUSD)
	assert.True(t, stats.UptimeSeconds >= 0)
}

func TestAnalyticsEmpty(t *testing.T) {
	a := NewAnalytics()
	stats := a.Stats()
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, float64(0), stats.HitRate)
}
