package action

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBlueGreenHandler_DefaultsToBlue(t *testing.T) {
	h := NewBlueGreenHandler(BlueGreenConfig{
		Blue:  UpstreamGroup{URL: "http://blue:8080"},
		Green: UpstreamGroup{URL: "http://green:8080"},
	})
	assert.Equal(t, "blue", h.ActiveGroup())
	assert.Equal(t, "http://blue:8080", h.ActiveURL())
}

func TestNewBlueGreenHandler_RespectsActive(t *testing.T) {
	h := NewBlueGreenHandler(BlueGreenConfig{
		Blue:   UpstreamGroup{URL: "http://blue:8080"},
		Green:  UpstreamGroup{URL: "http://green:8080"},
		Active: "green",
	})
	assert.Equal(t, "green", h.ActiveGroup())
	assert.Equal(t, "http://green:8080", h.ActiveURL())
}

func TestNewBlueGreenHandler_InvalidActiveDefaultsToBlue(t *testing.T) {
	h := NewBlueGreenHandler(BlueGreenConfig{
		Blue:   UpstreamGroup{URL: "http://blue:8080"},
		Green:  UpstreamGroup{URL: "http://green:8080"},
		Active: "invalid",
	})
	assert.Equal(t, "blue", h.ActiveGroup())
}

func TestBlueGreenHandler_Switch(t *testing.T) {
	h := NewBlueGreenHandler(BlueGreenConfig{
		Blue:   UpstreamGroup{URL: "http://blue:8080", Name: "blue-v1"},
		Green:  UpstreamGroup{URL: "http://green:8080", Name: "green-v2"},
		Active: "blue",
	})

	require.Equal(t, "blue", h.ActiveGroup())
	require.Equal(t, "http://blue:8080", h.ActiveURL())

	h.Switch()
	assert.Equal(t, "green", h.ActiveGroup())
	assert.Equal(t, "http://green:8080", h.ActiveURL())

	h.Switch()
	assert.Equal(t, "blue", h.ActiveGroup())
	assert.Equal(t, "http://blue:8080", h.ActiveURL())
}

func TestBlueGreenHandler_ConcurrentAccess(t *testing.T) {
	h := NewBlueGreenHandler(BlueGreenConfig{
		Blue:   UpstreamGroup{URL: "http://blue:8080"},
		Green:  UpstreamGroup{URL: "http://green:8080"},
		Active: "blue",
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = h.ActiveGroup()
			_ = h.ActiveURL()
		}()
		go func() {
			defer wg.Done()
			h.Switch()
		}()
	}
	wg.Wait()

	// After all goroutines complete, active should be either "blue" or "green"
	group := h.ActiveGroup()
	assert.Contains(t, []string{"blue", "green"}, group)
}
