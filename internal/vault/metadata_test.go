package vault

import (
	"sync"
	"testing"
	"time"
)

func TestMetadataTracker_Record(t *testing.T) {
	mt := NewMetadataTracker()

	mt.Record("api_key", "hashicorp")

	entry := mt.Get("api_key")
	if entry == nil {
		t.Fatal("Get(api_key) returned nil after Record")
	}
	if entry.Name != "api_key" {
		t.Errorf("Name = %q, want %q", entry.Name, "api_key")
	}
	if entry.Source != "hashicorp" {
		t.Errorf("Source = %q, want %q", entry.Source, "hashicorp")
	}
	if entry.ResolveCount != 1 {
		t.Errorf("ResolveCount = %d, want 1", entry.ResolveCount)
	}
	if entry.FirstResolved.IsZero() {
		t.Error("FirstResolved should not be zero")
	}
	if entry.LastResolved.IsZero() {
		t.Error("LastResolved should not be zero")
	}
}

func TestMetadataTracker_RecordMultiple(t *testing.T) {
	mt := NewMetadataTracker()

	mt.Record("api_key", "hashicorp")
	firstResolved := mt.Get("api_key").FirstResolved

	// Small sleep so timestamps differ
	time.Sleep(time.Millisecond)
	mt.Record("api_key", "hashicorp")
	mt.Record("api_key", "local")

	entry := mt.Get("api_key")
	if entry.ResolveCount != 3 {
		t.Errorf("ResolveCount = %d, want 3", entry.ResolveCount)
	}
	if entry.Source != "local" {
		t.Errorf("Source = %q, want %q (should be updated to latest)", entry.Source, "local")
	}
	if !entry.FirstResolved.Equal(firstResolved) {
		t.Error("FirstResolved should not change after subsequent records")
	}
	if !entry.LastResolved.After(firstResolved) {
		t.Error("LastResolved should be after FirstResolved")
	}
}

func TestMetadataTracker_GetNonExistent(t *testing.T) {
	mt := NewMetadataTracker()

	entry := mt.Get("nonexistent")
	if entry != nil {
		t.Error("Get() for nonexistent key should return nil")
	}
}

func TestMetadataTracker_GetReturnsCopy(t *testing.T) {
	mt := NewMetadataTracker()
	mt.Record("key", "source")

	entry1 := mt.Get("key")
	entry2 := mt.Get("key")

	// Modifying the returned entry should not affect the tracker
	entry1.ResolveCount = 999
	if entry2.ResolveCount == 999 {
		t.Error("Get() should return independent copies")
	}
}

func TestMetadataTracker_All(t *testing.T) {
	mt := NewMetadataTracker()

	mt.Record("key1", "vault-a")
	mt.Record("key2", "vault-b")
	mt.Record("key3", "vault-a")

	all := mt.All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d entries, want 3", len(all))
	}

	for _, name := range []string{"key1", "key2", "key3"} {
		if _, ok := all[name]; !ok {
			t.Errorf("All() missing key %q", name)
		}
	}

	// Modifying returned map should not affect tracker
	all["key1"].ResolveCount = 999
	original := mt.Get("key1")
	if original.ResolveCount == 999 {
		t.Error("All() should return independent copies")
	}
}

func TestMetadataTracker_Len(t *testing.T) {
	mt := NewMetadataTracker()

	if mt.Len() != 0 {
		t.Errorf("Len() = %d, want 0", mt.Len())
	}

	mt.Record("key1", "source")
	mt.Record("key2", "source")
	if mt.Len() != 2 {
		t.Errorf("Len() = %d, want 2", mt.Len())
	}

	// Recording same key again should not increase count
	mt.Record("key1", "source")
	if mt.Len() != 2 {
		t.Errorf("Len() = %d, want 2 (same key recorded again)", mt.Len())
	}
}

func TestMetadataTracker_Remove(t *testing.T) {
	mt := NewMetadataTracker()

	mt.Record("key1", "source")
	mt.Record("key2", "source")
	mt.Remove("key1")

	if mt.Len() != 1 {
		t.Errorf("Len() = %d after Remove, want 1", mt.Len())
	}
	if mt.Get("key1") != nil {
		t.Error("Get(key1) should return nil after Remove")
	}
	if mt.Get("key2") == nil {
		t.Error("Get(key2) should still exist after removing key1")
	}

	// Removing nonexistent key should not panic
	mt.Remove("nonexistent")
}

func TestMetadataTracker_ConcurrentAccess(t *testing.T) {
	mt := NewMetadataTracker()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := "key"
			mt.Record(name, "source")
			mt.Get(name)
			mt.All()
			mt.Len()
		}(i)
	}
	wg.Wait()

	entry := mt.Get("key")
	if entry == nil {
		t.Fatal("entry should exist after concurrent writes")
	}
	if entry.ResolveCount != 100 {
		t.Errorf("ResolveCount = %d, want 100 after 100 concurrent records", entry.ResolveCount)
	}
}
