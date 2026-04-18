package action

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanaryHandler_ZeroPercent(t *testing.T) {
	h := NewCanaryHandler(CanaryConfig{
		Stable:        UpstreamGroup{URL: "http://stable:8080"},
		Canary:        UpstreamGroup{URL: "http://canary:8080"},
		CanaryPercent: 0,
	})

	// All requests should go to stable
	for i := 0; i < 100; i++ {
		assert.Equal(t, "http://stable:8080", h.SelectUpstream())
	}
}

func TestCanaryHandler_HundredPercent(t *testing.T) {
	h := NewCanaryHandler(CanaryConfig{
		Stable:        UpstreamGroup{URL: "http://stable:8080"},
		Canary:        UpstreamGroup{URL: "http://canary:8080"},
		CanaryPercent: 100,
	})

	// All requests should go to canary
	for i := 0; i < 100; i++ {
		assert.Equal(t, "http://canary:8080", h.SelectUpstream())
	}
}

func TestCanaryHandler_FiftyPercent(t *testing.T) {
	h := NewCanaryHandler(CanaryConfig{
		Stable:        UpstreamGroup{URL: "http://stable:8080"},
		Canary:        UpstreamGroup{URL: "http://canary:8080"},
		CanaryPercent: 50,
	})

	canaryCount := 0
	iterations := 10000
	for i := 0; i < iterations; i++ {
		if h.SelectUpstream() == "http://canary:8080" {
			canaryCount++
		}
	}

	// With 50% split over 10k iterations, expect roughly 5000 +/- 500
	pct := float64(canaryCount) / float64(iterations) * 100
	assert.InDelta(t, 50.0, pct, 5.0, "expected ~50%% canary, got %.1f%%", pct)
}

func TestCanaryHandler_ClampNegative(t *testing.T) {
	h := NewCanaryHandler(CanaryConfig{
		Stable:        UpstreamGroup{URL: "http://stable:8080"},
		Canary:        UpstreamGroup{URL: "http://canary:8080"},
		CanaryPercent: -10,
	})
	// Clamped to 0, all stable
	assert.Equal(t, "http://stable:8080", h.SelectUpstream())
}

func TestCanaryHandler_ClampOver100(t *testing.T) {
	h := NewCanaryHandler(CanaryConfig{
		Stable:        UpstreamGroup{URL: "http://stable:8080"},
		Canary:        UpstreamGroup{URL: "http://canary:8080"},
		CanaryPercent: 150,
	})
	// Clamped to 100, all canary
	assert.Equal(t, "http://canary:8080", h.SelectUpstream())
}

func TestCanaryHandler_SetCanaryPercent(t *testing.T) {
	h := NewCanaryHandler(CanaryConfig{
		Stable:        UpstreamGroup{URL: "http://stable:8080"},
		Canary:        UpstreamGroup{URL: "http://canary:8080"},
		CanaryPercent: 0,
	})

	// Initially all stable
	assert.Equal(t, "http://stable:8080", h.SelectUpstream())

	// Set to 100%
	h.SetCanaryPercent(100)
	assert.Equal(t, "http://canary:8080", h.SelectUpstream())

	// Set back to 0%
	h.SetCanaryPercent(0)
	assert.Equal(t, "http://stable:8080", h.SelectUpstream())
}

func TestCanaryHandler_SetCanaryPercent_Clamps(t *testing.T) {
	h := NewCanaryHandler(CanaryConfig{
		Stable:        UpstreamGroup{URL: "http://stable:8080"},
		Canary:        UpstreamGroup{URL: "http://canary:8080"},
		CanaryPercent: 50,
	})

	h.SetCanaryPercent(-5)
	assert.Equal(t, "http://stable:8080", h.SelectUpstream())

	h.SetCanaryPercent(200)
	assert.Equal(t, "http://canary:8080", h.SelectUpstream())
}

func TestCanaryHandler_ConcurrentAccess(t *testing.T) {
	h := NewCanaryHandler(CanaryConfig{
		Stable:        UpstreamGroup{URL: "http://stable:8080"},
		Canary:        UpstreamGroup{URL: "http://canary:8080"},
		CanaryPercent: 50,
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = h.SelectUpstream()
		}()
		go func(pct int) {
			defer wg.Done()
			h.SetCanaryPercent(pct)
		}(i)
	}
	wg.Wait()
}
