package reqctx

import (
	"testing"
)

func TestSetSessionDataEntry_AcceptsUpToMaxEntries(t *testing.T) {
	sd := &SessionData{ID: "test-session"}

	// Fill up to the maximum allowed entries.
	for i := 0; i < MaxSessionDataEntries; i++ {
		key := "key-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		ok := sd.SetSessionDataEntry(key, i)
		if !ok {
			t.Fatalf("expected entry %d (key=%s) to be accepted, but it was rejected", i, key)
		}
	}

	if len(sd.Data) != MaxSessionDataEntries {
		t.Errorf("expected %d entries, got %d", MaxSessionDataEntries, len(sd.Data))
	}
}

func TestSetSessionDataEntry_RejectsOverLimit(t *testing.T) {
	sd := &SessionData{ID: "test-session-overflow"}

	// Fill exactly to the limit.
	for i := 0; i < MaxSessionDataEntries; i++ {
		key := "entry-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		sd.SetSessionDataEntry(key, i)
	}

	// The 101st entry (new key) should be rejected.
	ok := sd.SetSessionDataEntry("overflow-key", "should-fail")
	if ok {
		t.Error("expected 101st entry to be rejected, but it was accepted")
	}

	if len(sd.Data) != MaxSessionDataEntries {
		t.Errorf("expected exactly %d entries after rejection, got %d", MaxSessionDataEntries, len(sd.Data))
	}

	// Verify the overflow key was not stored.
	if _, exists := sd.Data["overflow-key"]; exists {
		t.Error("overflow key should not be present in Data")
	}
}

func TestSetSessionDataEntry_OverwriteDoesNotCountTowardLimit(t *testing.T) {
	sd := &SessionData{ID: "test-session-overwrite"}

	// Fill to capacity.
	for i := 0; i < MaxSessionDataEntries; i++ {
		key := "slot-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		sd.SetSessionDataEntry(key, i)
	}

	if len(sd.Data) != MaxSessionDataEntries {
		t.Fatalf("precondition failed: expected %d entries, got %d", MaxSessionDataEntries, len(sd.Data))
	}

	// Overwrite an existing key. This should succeed because it does not
	// increase the entry count.
	ok := sd.SetSessionDataEntry("slot-A0", "updated-value")
	if !ok {
		t.Error("expected overwrite of existing key to succeed, but it was rejected")
	}

	val, exists := sd.Data["slot-A0"]
	if !exists {
		t.Fatal("expected key 'slot-A0' to exist after overwrite")
	}
	if val != "updated-value" {
		t.Errorf("expected value 'updated-value', got %v", val)
	}

	// Entry count should remain unchanged.
	if len(sd.Data) != MaxSessionDataEntries {
		t.Errorf("expected entry count to remain %d after overwrite, got %d", MaxSessionDataEntries, len(sd.Data))
	}
}

func TestSetSessionDataEntry_NilDataInitialized(t *testing.T) {
	sd := &SessionData{ID: "nil-data-session"}

	// Data starts as nil. SetSessionDataEntry should lazily initialize it.
	ok := sd.SetSessionDataEntry("first", 1)
	if !ok {
		t.Error("expected first entry to succeed")
	}
	if sd.Data == nil {
		t.Error("expected Data map to be initialized, but it is nil")
	}
	if sd.Data["first"] != 1 {
		t.Errorf("expected value 1, got %v", sd.Data["first"])
	}
}
