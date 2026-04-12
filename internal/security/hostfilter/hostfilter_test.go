package hostfilter

import (
	"sync"
	"testing"
)

func TestCheck_ExactMatch(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"example.com", "api.staging.com"})

	if !hf.Check("example.com") {
		t.Error("expected exact match for example.com")
	}
	if !hf.Check("api.staging.com") {
		t.Error("expected exact match for api.staging.com")
	}
}

func TestCheck_UnknownHostnameRejected(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"example.com"})

	if hf.Check("unknown.com") {
		t.Error("expected unknown.com to be rejected")
	}
}

func TestCheck_PortStrippingFallback(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"example.com"})

	if !hf.Check("example.com:8080") {
		t.Error("expected example.com:8080 to pass via port stripping")
	}
}

func TestCheck_PortExactMatch(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"example.com:8080"})

	if !hf.Check("example.com:8080") {
		t.Error("expected exact match for example.com:8080")
	}
}

func TestCheck_WildcardMatch(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"*.example.com"})

	if !hf.Check("api.example.com") {
		t.Error("expected api.example.com to match *.example.com")
	}
	if !hf.Check("www.example.com") {
		t.Error("expected www.example.com to match *.example.com")
	}
}

func TestCheck_WildcardWithPort(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"*.example.com"})

	if !hf.Check("api.example.com:8080") {
		t.Error("expected api.example.com:8080 to match *.example.com via port strip + wildcard")
	}
}

func TestCheck_WildcardSingleLevelOnly(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"*.example.com"})

	// a.b.example.com checks *.b.example.com, NOT *.example.com
	// So it should not match our *.example.com entry
	if hf.Check("a.b.example.com") {
		t.Error("expected a.b.example.com NOT to match *.example.com (single-level only)")
	}
}

func TestCheck_CaseInsensitive(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"example.com"})

	if !hf.Check("Example.COM") {
		t.Error("expected case-insensitive match")
	}
	if !hf.Check("EXAMPLE.COM") {
		t.Error("expected case-insensitive match")
	}
}

func TestCheck_EmptyHostnameBypass(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"example.com"})

	if !hf.Check("") {
		t.Error("expected empty hostname to bypass filter")
	}
}

func TestReload_ReplacesFilterContents(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"first.com"})

	if !hf.Check("first.com") {
		t.Error("expected first.com to pass after initial load")
	}

	hf.Reload([]string{"second.com"})

	if hf.Check("first.com") {
		t.Error("expected first.com to be rejected after reload")
	}
	if !hf.Check("second.com") {
		t.Error("expected second.com to pass after reload")
	}
}

func TestAdd_ImmediatelyAvailable(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"example.com"})

	if hf.Check("new.com") {
		t.Error("expected new.com to be rejected before Add")
	}

	hf.Add("new.com")

	if !hf.Check("new.com") {
		t.Error("expected new.com to pass after Add")
	}
}

func TestSize(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{"a.com", "b.com", "c.com"})

	if hf.Size() != 3 {
		t.Errorf("expected size 3, got %d", hf.Size())
	}

	hf.Add("d.com")
	if hf.Size() != 4 {
		t.Errorf("expected size 4, got %d", hf.Size())
	}
}

func TestStats(t *testing.T) {
	hf := New(100, 0.01)
	hf.Reload([]string{"a.com", "b.com"})

	stats := hf.Stats()
	if stats.Size != 2 {
		t.Errorf("expected size 2, got %d", stats.Size)
	}
	if stats.EstimatedItems != 100 {
		t.Errorf("expected estimated_items 100, got %d", stats.EstimatedItems)
	}
	if stats.FPRate != 0.01 {
		t.Errorf("expected fp_rate 0.01, got %f", stats.FPRate)
	}
	if stats.LastRebuilt.IsZero() {
		t.Error("expected last_rebuilt to be set")
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	hf := New(1000, 0.001)
	hf.Reload([]string{"example.com"})

	var wg sync.WaitGroup
	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				hf.Check("example.com")
				hf.Check("unknown.com")
			}
		}()
	}
	// Concurrent writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hf.Add("new" + string(rune('a'+i)) + ".com")
		}(i)
	}
	// Concurrent reload
	wg.Add(1)
	go func() {
		defer wg.Done()
		hf.Reload([]string{"example.com", "other.com"})
	}()

	wg.Wait()
}

func TestNew_Defaults(t *testing.T) {
	hf := New(0, 0)
	if hf.estimatedItems != 10000 {
		t.Errorf("expected default estimatedItems 10000, got %d", hf.estimatedItems)
	}
	if hf.fpRate != 0.001 {
		t.Errorf("expected default fpRate 0.001, got %f", hf.fpRate)
	}
}
