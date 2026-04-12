package responsecache

import (
	"testing"
	"time"
)

func TestCacheTierAnalytics_RecordHitMiss(t *testing.T) {
	a := NewCacheTierAnalytics()

	a.RecordHit("memory", "origin-1")
	a.RecordHit("memory", "origin-1")
	a.RecordHit("memory", "origin-2")
	a.RecordMiss("memory", "origin-1")

	stats := a.Stats()
	s, ok := stats["memory"]
	if !ok {
		t.Fatal("expected stats for 'memory' tier")
	}
	if s.Hits != 3 {
		t.Errorf("expected 3 hits, got %d", s.Hits)
	}
	if s.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", s.Misses)
	}
}

func TestCacheTierAnalytics_HitRate(t *testing.T) {
	a := NewCacheTierAnalytics()

	// No data
	if rate := a.HitRate("empty"); rate != 0 {
		t.Errorf("expected 0%% hit rate for empty tier, got %.2f%%", rate)
	}

	// 3 hits, 1 miss = 75%
	a.RecordHit("redis", "origin-1")
	a.RecordHit("redis", "origin-1")
	a.RecordHit("redis", "origin-1")
	a.RecordMiss("redis", "origin-1")

	rate := a.HitRate("redis")
	if rate != 75.0 {
		t.Errorf("expected 75%% hit rate, got %.2f%%", rate)
	}

	// 100% hit rate
	a.RecordHit("disk", "origin-1")
	a.RecordHit("disk", "origin-1")
	if rate := a.HitRate("disk"); rate != 100.0 {
		t.Errorf("expected 100%% hit rate, got %.2f%%", rate)
	}

	// 0% hit rate (all misses)
	a.RecordMiss("cold", "origin-1")
	a.RecordMiss("cold", "origin-1")
	if rate := a.HitRate("cold"); rate != 0 {
		t.Errorf("expected 0%% hit rate, got %.2f%%", rate)
	}
}

func TestCacheTierAnalytics_Evictions(t *testing.T) {
	a := NewCacheTierAnalytics()

	a.RecordEviction("memory", "capacity")
	a.RecordEviction("memory", "capacity")
	a.RecordEviction("memory", "ttl_expired")

	stats := a.Stats()
	s, ok := stats["memory"]
	if !ok {
		t.Fatal("expected stats for 'memory' tier")
	}
	if s.Evictions != 3 {
		t.Errorf("expected 3 evictions, got %d", s.Evictions)
	}
}

func TestCacheTierAnalytics_UpdateSize(t *testing.T) {
	a := NewCacheTierAnalytics()

	a.UpdateSize("memory", 1024*1024)
	a.UpdateItemCount("memory", 500)

	stats := a.Stats()
	s := stats["memory"]
	if s.SizeBytes != 1024*1024 {
		t.Errorf("expected size 1MB, got %d", s.SizeBytes)
	}
	if s.ItemCount != 500 {
		t.Errorf("expected 500 items, got %d", s.ItemCount)
	}

	// Update to new value
	a.UpdateSize("memory", 2*1024*1024)
	stats = a.Stats()
	if stats["memory"].SizeBytes != 2*1024*1024 {
		t.Errorf("expected updated size 2MB, got %d", stats["memory"].SizeBytes)
	}
}

func TestCacheTierAnalytics_RecordLatency(t *testing.T) {
	a := NewCacheTierAnalytics()

	// Just ensure it does not panic; latency is recorded to prometheus histogram
	a.RecordLatency("memory", "get", 5*time.Millisecond)
	a.RecordLatency("memory", "put", 10*time.Millisecond)
	a.RecordLatency("redis", "get", 2*time.Millisecond)
}

func TestCacheTierAnalytics_MultipleTiers(t *testing.T) {
	a := NewCacheTierAnalytics()

	a.RecordHit("memory", "origin-1")
	a.RecordMiss("memory", "origin-1")
	a.RecordHit("redis", "origin-1")
	a.RecordHit("disk", "origin-1")

	stats := a.Stats()
	if len(stats) != 3 {
		t.Errorf("expected 3 tiers, got %d", len(stats))
	}

	if stats["memory"].Hits != 1 || stats["memory"].Misses != 1 {
		t.Errorf("unexpected memory stats: %+v", stats["memory"])
	}
	if stats["redis"].Hits != 1 || stats["redis"].Misses != 0 {
		t.Errorf("unexpected redis stats: %+v", stats["redis"])
	}
	if stats["disk"].Hits != 1 {
		t.Errorf("unexpected disk stats: %+v", stats["disk"])
	}
}
