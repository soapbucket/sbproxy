package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCacheControl_Empty(t *testing.T) {
	d := ParseCacheControl("")
	assert.False(t, d.NoCache)
	assert.False(t, d.NoStore)
	assert.False(t, d.ForceCache)
}

func TestParseCacheControl_NoCache(t *testing.T) {
	d := ParseCacheControl("no-cache")
	assert.True(t, d.NoCache)
	assert.False(t, d.NoStore)
	assert.False(t, d.ForceCache)
}

func TestParseCacheControl_NoStore(t *testing.T) {
	d := ParseCacheControl("no-store")
	assert.False(t, d.NoCache)
	assert.True(t, d.NoStore)
	assert.False(t, d.ForceCache)
}

func TestParseCacheControl_ForceCache(t *testing.T) {
	d := ParseCacheControl("force-cache")
	assert.False(t, d.NoCache)
	assert.False(t, d.NoStore)
	assert.True(t, d.ForceCache)
}

func TestParseCacheControl_Multiple(t *testing.T) {
	d := ParseCacheControl("no-cache, force-cache")
	assert.True(t, d.NoCache)
	assert.False(t, d.NoStore)
	assert.True(t, d.ForceCache)
}

func TestParseCacheControl_CaseInsensitive(t *testing.T) {
	d := ParseCacheControl("No-Cache")
	assert.True(t, d.NoCache)
}

func TestParseCacheControl_WithWhitespace(t *testing.T) {
	d := ParseCacheControl("  no-store  ,  force-cache  ")
	assert.True(t, d.NoStore)
	assert.True(t, d.ForceCache)
}

func TestParseCacheControl_UnknownDirective(t *testing.T) {
	d := ParseCacheControl("unknown-directive")
	assert.False(t, d.NoCache)
	assert.False(t, d.NoStore)
	assert.False(t, d.ForceCache)
}

func TestCacheDirective_ShouldRead(t *testing.T) {
	tests := []struct {
		name     string
		d        CacheDirective
		expected bool
	}{
		{"default", CacheDirective{}, true},
		{"no-cache", CacheDirective{NoCache: true}, false},
		{"no-store", CacheDirective{NoStore: true}, false},
		{"force-cache", CacheDirective{ForceCache: true}, true},
		{"no-cache+no-store", CacheDirective{NoCache: true, NoStore: true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.d.ShouldRead())
		})
	}
}

func TestCacheDirective_ShouldWrite(t *testing.T) {
	tests := []struct {
		name     string
		d        CacheDirective
		expected bool
	}{
		{"default", CacheDirective{}, true},
		{"no-cache", CacheDirective{NoCache: true}, true},
		{"no-store", CacheDirective{NoStore: true}, false},
		{"force-cache", CacheDirective{ForceCache: true}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.d.ShouldWrite())
		})
	}
}

func TestCacheDirective_Status(t *testing.T) {
	tests := []struct {
		name     string
		d        CacheDirective
		expected CacheStatus
	}{
		{"default", CacheDirective{}, CacheStatusMiss},
		{"no-cache", CacheDirective{NoCache: true}, CacheStatusBypass},
		{"no-store", CacheDirective{NoStore: true}, CacheStatusNoStore},
		{"no-store takes precedence", CacheDirective{NoCache: true, NoStore: true}, CacheStatusNoStore},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.d.Status())
		})
	}
}

func TestCacheStatus_Values(t *testing.T) {
	assert.Equal(t, CacheStatus("hit"), CacheStatusHit)
	assert.Equal(t, CacheStatus("miss"), CacheStatusMiss)
	assert.Equal(t, CacheStatus("semantic_hit"), CacheStatusSemanticHit)
	assert.Equal(t, CacheStatus("bypass"), CacheStatusBypass)
	assert.Equal(t, CacheStatus("no-store"), CacheStatusNoStore)
}

func TestHeaderConstants(t *testing.T) {
	assert.Equal(t, "X-Sb-Cache-Control", HeaderSBCacheControl)
	assert.Equal(t, "X-Sb-Cache-Status", HeaderSBCacheStatus)
}
